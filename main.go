package main

import (
    "log"

    "github.com/CaliDog/certstream-go"
    "github.com/nsqio/go-nsq"
    "github.com/xingda/ssl_mongo_project"
)

var logger = log.New(log.Writer(), "certstream-example: ", log.Lshortfile)

func publishToNSQ(domain string, producer *nsq.Producer) {
    err := producer.Publish("domain_names", []byte(domain))
    if err != nil {
        logger.Printf("Failed to publish domain to NSQ: %s", err)
    } else {
        logger.Printf("Successfully published domain to NSQ: %s", domain)
    }
}

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

    for _, domain := range allDomains {
        domainStr, ok := domain.(string)
        if ok {
            logger.Printf("Extracted domain: %s", domainStr)
            publishToNSQ(domainStr, producer)
            ssl_mongo_project.StoreCertstreamResult(domainStr)
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
