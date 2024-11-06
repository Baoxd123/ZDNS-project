package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/CaliDog/certstream-go"
	"github.com/nsqio/go-nsq"
	"github.com/xingda/ssl_mongo_project"
)

var logger = log.New(log.Writer(), "certstream-example: ", log.Lshortfile)

// Map to keep track of domain counts per second
var domainCountMap = make(map[string]int)
var mu sync.Mutex

// Log file for processing speed
var logFile *os.File

// Certstream counters per second
var certstreamCertCounter int
var certstreamDomainCounter int
var counterMutex sync.Mutex

// Publish domain information to NSQ with record_ID, with optional delay
func publishToNSQ(recordID, domain, timestamp string, producer *nsq.Producer, topic string, deferMs int) {
	// Create a JSON object with record_ID, domain, and timestamp
	message := map[string]string{
		"record_ID": recordID,
		"domain":    domain,
		"timestamp": timestamp,
	}

	messageJSON, err := json.Marshal(message)
	if err != nil {
		logger.Printf("Failed to marshal message to JSON: %s", err)
		return
	}

	if deferMs > 0 {
		// Use PublishDeferred for delayed messages
		err = producer.DeferredPublish(topic, time.Duration(deferMs)*time.Millisecond, messageJSON)
	} else {
		// Use Publish for real-time messages
		err = producer.Publish(topic, messageJSON)
	}

	if err != nil {
		logger.Printf("Failed to publish domain to NSQ topic %s: %s", topic, err)
	} else {
		logger.Printf("Successfully published domain to NSQ topic %s: %s", topic, messageJSON)
	}
}

// Handle certificate update by extracting domains and publishing them to NSQ
func handleCertificateUpdate(data map[string]interface{}, producer *nsq.Producer) {
	leafCert, ok := data["leaf_cert"].(map[string]interface{})
	if !ok {
		logger.Printf("Failed to get leaf_cert from JSON")
		return
	}

	allDomains, ok := leafCert["all_domains"].([]interface{})
	if !ok {
		logger.Printf("Failed to get all_domains from leaf_cert")
		return
	}

	// Increment certificate counter
	incrementCertstreamCertCounter()

	timestamp := time.Now().UTC().Format(time.RFC3339) // Generate the current timestamp in second precision, in UTC

	for _, domain := range allDomains {
		domainStr, ok := domain.(string)
		if ok {
			logger.Printf("Extracted domain: %s", domainStr)

			// Generate record_ID with counter if needed
			mu.Lock()
			key := fmt.Sprintf("%s_%s", timestamp, domainStr)
			counter := domainCountMap[key] + 1
			domainCountMap[key] = counter
			mu.Unlock()

			var recordID string
			if counter == 1 {
				recordID = fmt.Sprintf("%s_%s", timestamp, domainStr)
			} else {
				recordID = fmt.Sprintf("%s_%s_%d", timestamp, domainStr, counter)
			}

			// Publish to real-time NSQ topic
			publishToNSQ(recordID, domainStr, timestamp, producer, "domain_names", 0)
			incrementCertstreamDomainCounter() //record the real-time domain speed

			// Publish to delayed NSQ topics with different delays
			delayDurations := map[string]int{
				"nsq_delayed_1min":  60000,   // 1 minute delay in milliseconds
				"nsq_delayed_5min":  300000,  // 5 minutes delay in milliseconds
				"nsq_delayed_10min": 600000,  // 10 minutes delay in milliseconds
				"nsq_delayed_30min": 1800000, // 30 minutes delay in milliseconds
				"nsq_delayed_1hour": 3600000, // 1 hour delay in milliseconds
			}

			for topic, delayMs := range delayDurations {
				publishToNSQ(recordID, domainStr, timestamp, producer, topic, delayMs)

			}

			// Store the individual parts of the certificate in MongoDB along with the domain
			extensions, _ := leafCert["extensions"].(map[string]interface{})
			subject, _ := leafCert["subject"].(map[string]interface{})
			issuer, _ := leafCert["issuer"].(map[string]interface{})

			certData := map[string]interface{}{
				"store_timestamp":             timestamp,
				"record_ID":                   recordID,
				"domain":                      domainStr,
				"serial_number":               leafCert["serial_number"],
				"issuer_country":              issuer["C"],
				"issuer_common_name":          issuer["CN"],
				"issuer_organization":         issuer["O"],
				"issuer_organizational_unit":  issuer["OU"],
				"subject_country":             subject["C"],
				"subject_common_name":         subject["CN"],
				"subject_organization":        subject["O"],
				"subject_organizational_unit": subject["OU"],
				"not_before":                  leafCert["not_before"],
				"not_after":                   leafCert["not_after"],
				"fingerprint":                 leafCert["fingerprint"],
				"authority_info_access":       extensions["authorityInfoAccess"],
				"subject_alternative_names":   extensions["subjectAltName"],
				"basic_constraints":           extensions["basicConstraints"],
				"key_usage":                   extensions["keyUsage"],
				"extended_key_usage":          extensions["extendedKeyUsage"],
				"certificate_policies":        extensions["certificatePolicies"],
				"signature_algorithm":         leafCert["signature_algorithm"],
				"delayTime":                   "real-time, 1min, 5min, 10min, 30min, 1hour",
			}

			ssl_mongo_project.StoreCertstreamResult(certData)
			logger.Printf("Stored full certstream result in MongoDB: %v", certData)

		} else {
			logger.Printf("Invalid domain type")
		}
	}
}

// Increment Certstream certificate counter
func incrementCertstreamCertCounter() {
	counterMutex.Lock()
	certstreamCertCounter++
	counterMutex.Unlock()
}

// Increment Certstream domain counter
func incrementCertstreamDomainCounter() {
	counterMutex.Lock()
	certstreamDomainCounter++
	counterMutex.Unlock()
}

// Log statistics to the log file every second
func startCertstreamLogging() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		counterMutex.Lock()
		certstreamCertCount := certstreamCertCounter
		certstreamDomainCount := certstreamDomainCounter
		certstreamCertCounter = 0
		certstreamDomainCounter = 0
		counterMutex.Unlock()

		timestamp := time.Now().UTC().Format(time.RFC3339)
		logEntry := fmt.Sprintf("<certstream-cert, %d, %s>\n<certstream-domain-realTime, %d, %s>\n", certstreamCertCount, timestamp, certstreamDomainCount, timestamp)
		if _, err := logFile.WriteString(logEntry); err != nil {
			log.Printf("Failed to write to processing speed log file: %v", err)
		}
	}
}

func main() {
	ssl_mongo_project.InitMongoDB()

	producer, err := nsq.NewProducer("127.0.0.1:4150", nsq.NewConfig())
	if err != nil {
		log.Fatal("Failed to create NSQ producer:", err)
	}
	defer producer.Stop()

	// Initialize log file
	logFile, err = os.OpenFile("certstream_speed.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open processing speed log file: %v", err)
	}
	defer logFile.Close()

	// Start logging certstream processing speed
	go startCertstreamLogging()

	stream, errStream := certstream.CertStreamEventStream(false)

	for {
		select {
		case jq := <-stream:
			logger.Printf("Full certstream message: %v", jq)
			messageType, err := jq.String("message_type")
			if err != nil {
				logger.Fatal("Error decoding message type")
			}

			if messageType == "certificate_update" {
				rawData, err := jq.Interface()
				if err != nil {
					logger.Printf("Failed to get interface from jq: %s", err)
					continue
				}

				data, ok := rawData.(map[string]interface{})
				if !ok {
					logger.Printf("Failed to convert to map[string]interface{}")
					continue
				}
				handleCertificateUpdate(data["data"].(map[string]interface{}), producer)
			}

		case err := <-errStream:
			logger.Printf("Error from certstream: %s", err)
		}
	}
}
