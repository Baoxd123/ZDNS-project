package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nsqio/go-nsq"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const BatchSize = 100 // Set batch size

// ZDNS query result structure
type ZDNSResult struct {
	Name    string `json:"name"`
	Results struct {
		A struct {
			Data struct {
				Answers []struct {
					Address string `json:"answer"`
					Type    string `json:"type"`
				} `json:"answers"`
			} `json:"data"`
			Status    string `json:"status"`
			Timestamp string `json:"timestamp"`
		} `json:"A"`
	} `json:"results"`
}

// ZGrab2 result structure
type ZGrab2Result struct {
	Domain        string   `json:"domain"`
	IPAddress     string   `json:"ip_address"`
	Success       bool     `json:"success"`
	RawOutput     string   `json:"raw_output"`
	RecordID      string   `json:"record_ID"`
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	SANs          []string `json:"sans"`
	ValidityStart string   `json:"validity_start"`
	ValidityEnd   string   `json:"validity_end"`
}

var (
	mongoClient        *mongo.Client
	delayedProducer    *nsq.Producer
	dnsProducer        *nsq.Producer
	zdnsCollection     *mongo.Collection
	zgrabCollection    *mongo.Collection
	logFile            *os.File
	zdnsCounter        int
	zdnsIPCounter      int
	zdnsPublishCounter int
	zgrabCounter       int
	counterMutex       sync.Mutex
)

// Initialize MongoDB connection
func initMongoDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	mongoClient = client
	zdnsCollection = client.Database("ssl_project").Collection("zdns_results")
	zgrabCollection = client.Database("ssl_project").Collection("zgrab2_results")
}

// Generate a random string of a given length
func generateRandomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Log statistics to the log file every second
func startLogging() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		counterMutex.Lock()
		zdnsCount := zdnsCounter
		zdnsIPCount := zdnsIPCounter
		zdnsPublishCount := zdnsPublishCounter
		zgrabCount := zgrabCounter
		zdnsCounter = 0
		zdnsIPCounter = 0
		zdnsPublishCounter = 0
		zgrabCounter = 0
		counterMutex.Unlock()

		timestamp := time.Now().UTC().Format(time.RFC3339)
		logEntry := fmt.Sprintf("<zdns-domain-processed, %d, %s>\n<zdns-ip-generated, %d, %s>\n<zdns-publishTOZgrab, %d, %s>\n<zgrab-processed, %d, %s>\n", zdnsCount, timestamp, zdnsIPCount, timestamp, zdnsPublishCount, timestamp, zgrabCount, timestamp)
		if _, err := logFile.WriteString(logEntry); err != nil {
			log.Printf("Failed to write to log file: %v", err)
		}
	}
}

// Process domain queries in batches
func handleBatch(domains []string, recordIDs []string, isDelayed bool, delayLabel string) {
	// Create a map to store domain and recordID relationships
	domainMap := make(map[string]string)
	for i, domain := range domains {
		// Replace wildcard (*) with a random string to avoid accidental matches
		if strings.HasPrefix(domain, "*.") {
			randomSubdomain := generateRandomString(10)
			domain = strings.Replace(domain, "*", randomSubdomain, 1)
		}
		domainMap[domain] = recordIDs[i]
		domains[i] = domain // Update the domains slice with the modified domain
	}

	// Use ZDNS batch query command
	cmd := exec.Command("zdns", "A")
	cmd.Stdin = strings.NewReader(strings.Join(domains, "\n")) // Add all domains to the ZDNS query
	out, err := cmd.Output()
	if err != nil {
		log.Printf("ZDNS batch query failed: %v", err)
		// Store failure for all domains
		for originalDomain, recordID := range domainMap {
			storeResult(time.Now().UTC().Format(time.RFC3339), originalDomain, "Batch Query Failed", recordID, delayLabel, isDelayed)
		}
		return
	}

	// Parse ZDNS output line by line
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue // Skip empty lines
		}

		var result ZDNSResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("Failed to unmarshal ZDNS result: %v", err)
			// Even if unmarshaling fails, store the failure info with correct record ID
			if recordID, exists := domainMap[result.Name]; exists {
				storeResult(time.Now().UTC().Format(time.RFC3339), result.Name, "Unmarshal Error", recordID, delayLabel, isDelayed)
			}
			continue
		}

		// Check and store results
		if recordID, exists := domainMap[result.Name]; exists {
			incrementZDNSCounter() // Increment domain counter
			if result.Results.A.Status == "NOERROR" && len(result.Results.A.Data.Answers) > 0 {
				// Store all <domain, ip> pairs in MongoDB
				for _, answer := range result.Results.A.Data.Answers {
					if answer.Type == "A" {
						storeResult(result.Results.A.Timestamp, result.Name, answer.Address, recordID, delayLabel, isDelayed)
						incrementZDNSIPCounter() // Increment IP counter
					}
				}

				// Randomly select one <domain, ip> pair to publish to ZDNS queue
				if len(result.Results.A.Data.Answers) > 0 {
					randomIndex := rand.Intn(len(result.Results.A.Data.Answers))
					selectedAnswer := result.Results.A.Data.Answers[randomIndex]
					if selectedAnswer.Type == "A" {
						publishToZDNSQueue(result.Name, selectedAnswer.Address, recordID, result.Results.A.Timestamp, delayLabel)
						incrementZDNSPublishCounter() // Increment publish counter
					}
				}
			} else {
				storeResult(result.Results.A.Timestamp, result.Name, result.Results.A.Status, recordID, delayLabel, isDelayed)
			}
		}
	}
}

// Publish domain and IP to new NSQ queue
func publishToZDNSQueue(domain, ipAddress, recordID, timestamp, delayLabel string) {
	data := map[string]string{
		"domain":     domain,
		"ip_address": ipAddress,
		"record_ID":  recordID,
		"timestamp":  timestamp,
		"delay_time": delayLabel,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal data for zdns_domain_ip queue: %v", err)
		return
	}

	err = dnsProducer.Publish("zdns_domain_ip", jsonData)
	if err != nil {
		log.Printf("Failed to publish to zdns_domain_ip queue: %v", err)
	}
}

// Store result in MongoDB and print
func storeResult(timestamp, domain, ip, recordID, delayLabel string, isDelayed bool) {
	timestamp = time.Now().UTC().Format(time.RFC3339) // Convert timestamp to UTC format
	fmt.Printf("<%s, %s, %s, %s, %s>\n", timestamp, domain, ip, recordID, delayLabel)

	_, err := zdnsCollection.InsertOne(context.Background(), map[string]interface{}{
		"timestamp":  timestamp,
		"domain":     domain,
		"ip":         ip,
		"record_ID":  recordID,
		"delay_time": delayLabel,
	})
	if err != nil {
		log.Printf("Failed to insert into MongoDB: %s", err)
	}
}

// Increment ZDNS domain counter
func incrementZDNSCounter() {
	counterMutex.Lock()
	zdnsCounter++
	counterMutex.Unlock()
}

// Increment ZDNS IP counter
func incrementZDNSIPCounter() {
	counterMutex.Lock()
	zdnsIPCounter++
	counterMutex.Unlock()
}

// Increment ZDNS publish counter
func incrementZDNSPublishCounter() {
	counterMutex.Lock()
	zdnsPublishCounter++
	counterMutex.Unlock()
}

// Increment ZGrab counter
func incrementZGrabCounter() {
	counterMutex.Lock()
	zgrabCounter++
	counterMutex.Unlock()
}

// Worker function to handle ZGrab2sentinel tasks from NSQ
func zgrabWorker(id int, jobs <-chan *nsq.Message, wg *sync.WaitGroup) {
	defer wg.Done()

	for msg := range jobs {
		// Parse the JSON message to extract domain and IP
		var messageData struct {
			Domain    string `json:"domain"`
			IPAddress string `json:"ip_address"`
			RecordID  string `json:"record_ID"`
			Timestamp string `json:"timestamp"`
			DelayTime string `json:"delay_time"`
		}
		if err := json.Unmarshal(msg.Body, &messageData); err != nil {
			log.Printf("Failed to unmarshal ZGrab2 NSQ message: %v", err)
			msg.Finish()
			continue
		}

		// Corrected to use zgrab2sentinel tls with domain and IP address as input from stdin
		cmd := exec.Command("zgrab2sentinel", "tls", "--port", "443", "--timeout", "10s")
		// Provide IP and domain as input in the required format
		cmd.Stdin = strings.NewReader(fmt.Sprintf("%s, %s", messageData.IPAddress, messageData.Domain))
		out, err := cmd.CombinedOutput() // Use CombinedOutput to capture both stdout and stderr
		if err != nil {
			log.Printf("ZGrab2sentinel failed for domain %s (IP: %s): %v - Output: %s", messageData.Domain, messageData.IPAddress, err, string(out))
			storeZGrabResult(messageData.Domain, messageData.IPAddress, false, string(out), messageData.RecordID)
			msg.Finish()
			continue
		}

		// Store the entire ZGrab2sentinel output
		storeZGrabResult(messageData.Domain, messageData.IPAddress, true, string(out), messageData.RecordID)
		incrementZGrabCounter()
		msg.Finish()
	}
}

// Store ZGrab2 result in MongoDB
func storeZGrabResult(domain, ipAddress string, success bool, rawOutput, recordID string) {
	// Extract the JSON part from raw_output using a regular expression
	re := regexp.MustCompile(`(?m)^\{.*\}$`)
	matches := re.FindString(rawOutput)

	if matches == "" {
		log.Printf("Failed to extract JSON from raw output for domain %s", domain)
		return
	}

	// Define struct to parse the certificate data
	type ParsedCertificate struct {
		Version            int    `json:"version"`
		SerialNumber       string `json:"serial_number"`
		SignatureAlgorithm struct {
			Name string `json:"name"`
			OID  string `json:"oid"`
		} `json:"signature_algorithm"`
		Issuer struct {
			CommonName   string `json:"common_name"`
			Country      string `json:"country"`
			Organization string `json:"organization"`
		} `json:"issuer"`
		Validity struct {
			Start  string `json:"start"`
			End    string `json:"end"`
			Length int    `json:"length"`
		} `json:"validity"`
		Subject struct {
			CommonName string `json:"common_name"`
		} `json:"subject"`
		Fingerprints struct {
			SHA256 string `json:"sha256"`
			MD5    string `json:"md5"`
			SHA1   string `json:"sha1"`
		} `json:"fingerprints"`
	}

	type Extensions struct {
		KeyUsage struct {
			DigitalSignature bool `json:"digital_signature"`
			Value            int  `json:"value"`
		} `json:"key_usage"`
		BasicConstraints struct {
			IsCA bool `json:"is_ca"`
		} `json:"basic_constraints"`
		SubjectAltName struct {
			DNSNames []string `json:"dns_names"`
		} `json:"subject_alt_name"`
		AuthorityKeyID string `json:"authority_key_id"`
		SubjectKeyID   string `json:"subject_key_id"`
	}

	type TLSResult struct {
		HandshakeLog struct {
			ServerCertificates struct {
				Certificate struct {
					Raw    string            `json:"raw"`
					Parsed ParsedCertificate `json:"parsed"`
				} `json:"certificate"`
				Extensions Extensions `json:"extensions"`
			} `json:"server_certificates"`
		} `json:"handshake_log"`
	}

	var output struct {
		Data struct {
			TLS TLSResult `json:"tls"`
		} `json:"data"`
	}

	// Parse the JSON data
	if err := json.Unmarshal([]byte(matches), &output); err != nil {
		log.Printf("Failed to unmarshal TLS data for domain %s: %v", domain, err)
		return
	}

	// Extract certificate information
	certificate := output.Data.TLS.HandshakeLog.ServerCertificates.Certificate
	extensions := output.Data.TLS.HandshakeLog.ServerCertificates.Extensions

	// Print the fields to be stored for debugging purposes
	fmt.Printf("<%s, %s, %t, %s, %+v>\n", domain, ipAddress, success, recordID, certificate)

	// Store the parsed result along with the complete raw output into MongoDB
	_, err := zgrabCollection.InsertOne(context.Background(), map[string]interface{}{
		"domain":     domain,
		"ip_address": ipAddress,
		"certificate": map[string]interface{}{
			"raw": certificate.Raw,
			"parsed": map[string]interface{}{
				"version":             certificate.Parsed.Version,
				"serial_number":       certificate.Parsed.SerialNumber,
				"signature_algorithm": certificate.Parsed.SignatureAlgorithm,
				"issuer":              certificate.Parsed.Issuer,
				"validity":            certificate.Parsed.Validity,
				"subject":             certificate.Parsed.Subject,
				"fingerprints":        certificate.Parsed.Fingerprints,
			},
			"extensions": map[string]interface{}{
				"key_usage":         extensions.KeyUsage,
				"basic_constraints": extensions.BasicConstraints,
				"subject_alt_name":  extensions.SubjectAltName,
				"authority_key_id":  extensions.AuthorityKeyID,
				"subject_key_id":    extensions.SubjectKeyID,
			},
		},
		"record_id": recordID,
		"raw_data":  rawOutput, // Store the entire raw output in a separate field called "raw_data"
	})
	if err != nil {
		log.Printf("Failed to insert ZGrab2 result into MongoDB: %s", err)
	}
}

// Worker function to process messages in batches
func worker(id int, jobs <-chan *nsq.Message, wg *sync.WaitGroup, isDelayed bool, delayLabel string) {
	defer wg.Done()

	// Initialize buffer and counter
	var domains []string
	var recordIDs []string
	counter := 0

	for msg := range jobs {
		// Parse the JSON message to extract domain and record_ID
		var messageData struct {
			RecordID  string `json:"record_ID"`
			Domain    string `json:"domain"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(msg.Body, &messageData); err != nil {
			log.Printf("Failed to unmarshal NSQ message: %v", err)
			msg.Finish()
			continue
		}

		// If this is a delayed worker, check the timestamp
		// In fact, it can be removed

		domain := messageData.Domain
		recordID := messageData.RecordID

		domains = append(domains, domain)
		recordIDs = append(recordIDs, recordID)
		counter++

		// If the buffer reaches the batch size, execute ZDNS batch query
		if counter >= BatchSize {
			log.Printf("[Worker %d] Processing batch of %d domains.", id, counter)
			handleBatch(domains, recordIDs, isDelayed, delayLabel)
			domains = nil   // Clear buffer
			recordIDs = nil // Clear record IDs buffer
			counter = 0     // Reset counter
		}

		msg.Finish()
	}

	// Process remaining messages
	if counter > 0 {
		log.Printf("[Worker %d] Processing remaining %d domains.", id, counter)
		handleBatch(domains, recordIDs, isDelayed, delayLabel)
	}
}

func main() {
	// Initialize MongoDB
	initMongoDB()
	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			log.Fatal(err)
		}
	}()

	// Initialize log file
	var err error
	logFile, err = os.OpenFile("zdns_zgrab_speed.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Start logging statistics
	go startLogging()

	// Create NSQ producer for delayed re-publish
	producer, err := nsq.NewProducer("127.0.0.1:4150", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create NSQ producer:", err)
	}
	delayedProducer = producer

	// Create NSQ producer for ZDNS queue
	dnsProducer, err = nsq.NewProducer("127.0.0.1:4150", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create ZDNS NSQ producer:", err)
	}

	// Number of worker goroutines
	numWorkers := 20
	numZgrabWorkers := 2000

	// Create NSQ consumer for real-time processing
	realTimeConsumer, err := nsq.NewConsumer("domain_names", "channel", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create NSQ real-time consumer:", err)
	}

	// Create a channel to pass jobs to real-time workers
	realTimeJobs := make(chan *nsq.Message, numWorkers)

	// Create a wait group to manage real-time workers
	var realTimeWG sync.WaitGroup

	// Start real-time worker goroutines
	for w := 1; w <= numWorkers; w++ {
		realTimeWG.Add(1)
		go worker(w, realTimeJobs, &realTimeWG, false, "real-time")
	}

	// Handle messages received from real-time NSQ
	realTimeConsumer.AddHandler(nsq.HandlerFunc(func(message *nsq.Message) error {
		realTimeJobs <- message
		return nil
	}))

	// Connect to nsqlookupd service for real-time consumer
	err = realTimeConsumer.ConnectToNSQLookupd("127.0.0.1:4161")
	if err != nil {
		log.Fatal("Failed to connect to nsqlookupd for real-time consumer:", err)
	}

	// Create NSQ consumers for delayed processing
	delayedTopics := []string{"nsq_delayed_1min", "nsq_delayed_5min", "nsq_delayed_10min", "nsq_delayed_30min", "nsq_delayed_1hour"}
	delayedLabels := []string{"1min", "5min", "10min", "30min", "1hour"}

	// Create a wait group to manage delayed workers
	var delayedWG sync.WaitGroup

	for i, topic := range delayedTopics {
		consumer, err := nsq.NewConsumer(topic, "channel", nsq.NewConfig())
		if err != nil {
			log.Fatal("Failed to create NSQ delayed consumer for topic ", topic, ":", err)
		}

		// Create a channel to pass jobs to delayed workers
		delayedJobs := make(chan *nsq.Message, numWorkers)

		// Start delayed worker goroutines
		for w := 1; w <= numWorkers; w++ {
			delayedWG.Add(1)
			go worker(w, delayedJobs, &delayedWG, true, delayedLabels[i])
		}

		// Handle messages received from delayed NSQ
		consumer.AddHandler(nsq.HandlerFunc(func(message *nsq.Message) error {
			delayedJobs <- message
			return nil
		}))

		// Connect to nsqlookupd service for delayed consumer
		err = consumer.ConnectToNSQLookupd("127.0.0.1:4161")
		if err != nil {
			log.Fatal("Failed to connect to nsqlookupd for delayed consumer for topic ", topic, ":", err)
		}
	}

	// Create NSQ consumer for zdns_domain_ip
	zdnsConsumer, err := nsq.NewConsumer("zdns_domain_ip", "channel", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create NSQ zdns_domain_ip consumer:", err)
	}

	// Create a channel to pass jobs to zgrab workers
	zgrabJobs := make(chan *nsq.Message, numWorkers)

	// Create a wait group to manage ZGrab workers
	var zgrabWG sync.WaitGroup

	// Start ZGrab worker goroutines
	for w := 1; w <= numZgrabWorkers; w++ {
		zgrabWG.Add(1)
		go zgrabWorker(w, zgrabJobs, &zgrabWG)
	}

	// Handle messages received from zdns_domain_ip NSQ
	zdnsConsumer.AddHandler(nsq.HandlerFunc(func(message *nsq.Message) error {
		zgrabJobs <- message
		return nil
	}))

	// Connect to nsqlookupd service for zdns_domain_ip consumer
	err = zdnsConsumer.ConnectToNSQLookupd("127.0.0.1:4161")
	if err != nil {
		log.Fatal("Failed to connect to nsqlookupd for zdns_domain_ip consumer:", err)
	}

	log.Printf("Started %d workers for real-time, delayed, and ZGrab2 processing.", numWorkers)

	// Wait for workers to finish (which they never will in this case)
	realTimeWG.Wait()
	delayedWG.Wait()
	zgrabWG.Wait()
}
