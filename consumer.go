package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
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

var (
	mongoClient    *mongo.Client
	zdnsCollection *mongo.Collection
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
}

// Process domain queries in batches
func handleBatch(domains []string) {
	// Use ZDNS batch query command
	cmd := exec.Command("zdns", "A")
	cmd.Stdin = strings.NewReader(strings.Join(domains, "\n")) // Add all domains to the ZDNS query
	out, err := cmd.Output()
	if err != nil {
		log.Printf("ZDNS batch query failed: %v", err)
		storeBatchResults(time.Now().Format(time.RFC3339), domains, []string{"None"})
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
			continue
		}

		// Check and store results
		if result.Results.A.Status == "NOERROR" && len(result.Results.A.Data.Answers) > 0 {
			for _, answer := range result.Results.A.Data.Answers {
				if answer.Type == "A" {
					storeResult(result.Results.A.Timestamp, result.Name, answer.Address)
				}
			}
		} else {
			storeResult(time.Now().Format(time.RFC3339), result.Name, "None")
		}
	}
}

// Store batch results in MongoDB
func storeBatchResults(timestamp string, domains []string, ips []string) {
	for i := 0; i < len(domains); i++ {
		ip := "None"
		if i < len(ips) {
			ip = ips[i]
		}
		storeResult(timestamp, domains[i], ip)
	}
}

// Store result in MongoDB and print
func storeResult(timestamp, domain, ip string) {
	fmt.Printf("<%s, %s, %s>\n", timestamp, domain, ip)

	_, err := zdnsCollection.InsertOne(context.Background(), map[string]interface{}{
		"timestamp": timestamp,
		"domain":    domain,
		"ip":        ip,
	})
	if err != nil {
		log.Printf("Failed to insert into MongoDB: %s", err)
	}
}

// Worker function to process messages in batches
func worker(id int, jobs <-chan *nsq.Message, wg *sync.WaitGroup) {
	defer wg.Done()

	// Initialize buffer and counter
	var domains []string
	counter := 0

	for msg := range jobs {
		domain := string(msg.Body)
		domains = append(domains, domain)
		counter++

		// If the buffer reaches the batch size, execute ZDNS batch query
		if counter >= BatchSize {
			handleBatch(domains)
			domains = nil // Clear buffer
			counter = 0   // Reset counter
		}

		msg.Finish()
	}

	// Process remaining messages
	if counter > 0 {
		handleBatch(domains)
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

	// Number of worker goroutines
	numWorkers := 20

	// Create NSQ consumer
	config := nsq.NewConfig()
	config.MaxInFlight = numWorkers * 2 // Adjust this value as needed
	consumer, err := nsq.NewConsumer("domain_names", "channel", config)
	if err != nil {
		log.Fatal("Failed to create NSQ consumer:", err)
	}

	// Create a channel to pass jobs to workers
	jobs := make(chan *nsq.Message, numWorkers)

	// Create a wait group to manage workers
	var wg sync.WaitGroup

	// Start worker goroutines
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go worker(w, jobs, &wg)
	}

	// Handle messages received from NSQ
	consumer.AddHandler(nsq.HandlerFunc(func(message *nsq.Message) error {
		jobs <- message
		return nil
	}))

	// Connect to nsqlookupd service
	err = consumer.ConnectToNSQLookupd("127.0.0.1:4161")
	if err != nil {
		log.Fatal("Failed to connect to nsqlookupd:", err)
	}

	log.Printf("Started %d workers. Processing messages...\n", numWorkers)

	// Wait for workers to finish (which they never will in this case)
	wg.Wait()
}
