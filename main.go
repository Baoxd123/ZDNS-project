package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/CaliDog/certstream-go"
	"github.com/nsqio/go-nsq"
	"github.com/xingda/ssl_mongo_project"
)

var logger = log.New(log.Writer(), "certstream-example: ", log.Lshortfile)

// Publish domain information to NSQ with record_ID
func publishToNSQ(recordID, domain string, producer *nsq.Producer) {
	// Create a JSON object with record_ID and domain
	message := map[string]string{
		"record_ID": recordID,
		"domain":    domain,
	}

	messageJSON, err := json.Marshal(message)
	if err != nil {
		logger.Printf("Failed to marshal message to JSON: %s", err)
		return
	}

	err = producer.Publish("domain_names", messageJSON)
	if err != nil {
		logger.Printf("Failed to publish domain to NSQ: %s", err)
	} else {
		logger.Printf("Successfully published domain to NSQ: %s", messageJSON)
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

	timestamp := time.Now().Format(time.RFC3339) // Generate the current timestamp

	for _, domain := range allDomains {
		domainStr, ok := domain.(string)
		if ok {
			logger.Printf("Extracted domain: %s", domainStr)

			// Create record_ID using timestamp and domain
			recordID := fmt.Sprintf("%s_%s", timestamp, domainStr)

			// Publish to NSQ with record_ID and domain
			publishToNSQ(recordID, domainStr, producer)

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
			}

			ssl_mongo_project.StoreCertstreamResult(certData)
			logger.Printf("Stored full certstream result in MongoDB: %v", certData)

		} else {
			logger.Printf("Invalid domain type")
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
