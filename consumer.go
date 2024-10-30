package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
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
	mongoClient     *mongo.Client
	delayedProducer *nsq.Producer
	zdnsCollection  *mongo.Collection
	zgrabCollection *mongo.Collection
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
			if result.Results.A.Status == "NOERROR" && len(result.Results.A.Data.Answers) > 0 {
				for _, answer := range result.Results.A.Data.Answers {
					if answer.Type == "A" {
						storeResult(result.Results.A.Timestamp, result.Name, answer.Address, recordID, delayLabel, isDelayed)
						// Call ZGrab2 for further processing of the IP address
						handleZGrab2(result.Name, answer.Address, recordID)
					}
				}
			} else {
				storeResult(result.Results.A.Timestamp, result.Name, result.Results.A.Status, recordID, delayLabel, isDelayed)
			}
		}
	}
}

// Modified ZGrab2 result parsing to store SSL certificate details in MongoDB.
func handleZGrab2(domain, ipAddress, recordID string) {
	// Corrected to use zgrab2 tls with IP address as input from stdin
	cmd := exec.Command("zgrab2", "tls", "--port", "443", "--timeout", "10s")
	cmd.Stdin = strings.NewReader(ipAddress) // Provide IP as input
	out, err := cmd.CombinedOutput()         // Use CombinedOutput to capture both stdout and stderr
	if err != nil {
		log.Printf("ZGrab2 failed for domain %s (IP: %s): %v - Output: %s", domain, ipAddress, err, string(out))
		storeZGrabResult(domain, ipAddress, false, string(out), recordID, "", "", nil, "", "")
		return
	}

	// Extract required fields from ZGrab2 output using regex
	output := string(out)
	issuerCommonName := extractField(output, `"issuer":\s*\{.*?"common_name":\s*"(.*?)"`)
	subjectCommonName := extractField(output, `"subject_dn":\s*"(.*?)"`)
	//keyUsage := extractField(output, `"key_usage":\s*\{.*?"value":\s*"(.*?)"`)
	subjectAltNames := extractField(output, `"subject_alt_name":\s*\{.*?"dns_names":\s*\[(.*?)\]`)
	validityStart := extractField(output, `"validity":\s*\{.*?"start":\s*"(.*?)"`)
	validityEnd := extractField(output, `"validity":\s*\{.*?"end":\s*"(.*?)"`)

	// Store the extracted fields in MongoDB
	storeZGrabResult(domain, ipAddress, true, output, recordID, issuerCommonName, subjectCommonName,
		[]string{subjectAltNames}, validityStart, validityEnd)
}

// Utility function to extract fields using regex
func extractField(input, regexPattern string) string {
	re := regexp.MustCompile(regexPattern)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// Store ZGrab2 result in MongoDB
func storeZGrabResult(domain, ipAddress string, success bool, rawOutput, recordID, issuer, subject string, sans []string, validityStart, validityEnd string) {
	fmt.Printf("<%s, %s, %t, %s, %s, %s, %s, %v, %s, %s>\n", domain, ipAddress, success, rawOutput, recordID, issuer, subject, sans, validityStart, validityEnd)

	_, err := zgrabCollection.InsertOne(context.Background(), map[string]interface{}{
		"domain":         domain,
		"ip_address":     ipAddress,
		"success":        success,
		"raw_output":     rawOutput,
		"record_ID":      recordID,
		"issuer":         issuer,
		"subject":        subject,
		"sans":           sans,
		"validity_start": validityStart,
		"validity_end":   validityEnd,
	})
	if err != nil {
		log.Printf("Failed to insert ZGrab2 result into MongoDB: %s - Data: domain=%s, ip_address=%s, success=%t, raw_output=%s, record_ID=%s", err, domain, ipAddress, success, rawOutput, recordID)
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
		if isDelayed {
			receivedTimestamp, err := time.Parse(time.RFC3339, messageData.Timestamp)
			if err != nil {
				log.Printf("Failed to parse timestamp: %v", err)
				msg.Finish()
				continue
			}
			difference := time.Since(receivedTimestamp)
			switch delayLabel {
			case "1min":
				if difference < time.Minute {
					// If the message is too early, re-publish it to the delayed topic
					log.Printf("[Worker %d] Message is too early, re-publishing to 1min delayed queue: %s", id, messageData.Domain)
					delayedProducer.Publish("nsq_delayed_1min", msg.Body)
					msg.Finish()
					continue
				}
			case "5min":
				if difference < 5*time.Minute {
					log.Printf("[Worker %d] Message is too early, re-publishing to 5min delayed queue: %s", id, messageData.Domain)
					delayedProducer.Publish("nsq_delayed_5min", msg.Body)
					msg.Finish()
					continue
				}
			case "10min":
				if difference < 10*time.Minute {
					log.Printf("[Worker %d] Message is too early, re-publishing to 10min delayed queue: %s", id, messageData.Domain)
					delayedProducer.Publish("nsq_delayed_10min", msg.Body)
					msg.Finish()
					continue
				}
			case "30min":
				if difference < 30*time.Minute {
					log.Printf("[Worker %d] Message is too early, re-publishing to 30min delayed queue: %s", id, messageData.Domain)
					delayedProducer.Publish("nsq_delayed_30min", msg.Body)
					msg.Finish()
					continue
				}
			case "1hour":
				if difference < time.Hour {
					log.Printf("[Worker %d] Message is too early, re-publishing to 1hour delayed queue: %s", id, messageData.Domain)
					delayedProducer.Publish("nsq_delayed_1hour", msg.Body)
					msg.Finish()
					continue
				}
			}
		}

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

	// Create NSQ producer for delayed re-publish
	producer, err := nsq.NewProducer("127.0.0.1:4150", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create NSQ producer:", err)
	}
	delayedProducer = producer

	// Number of worker goroutines
	numWorkers := 20

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

	log.Printf("Started %d workers for real-time and delayed processing.", numWorkers)

	// Wait for workers to finish (which they never will in this case)
	realTimeWG.Wait()
	delayedWG.Wait()
}
