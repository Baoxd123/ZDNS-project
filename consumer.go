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

// Handle received domain and query through ZDNS
func handleDomain(domain string) {
	cmd := exec.Command("zdns", "A")
	cmd.Stdin = strings.NewReader(domain)
	out, err := cmd.Output()
	if err != nil {
		storeResult(time.Now().Format(time.RFC3339), domain, "None")
		return
	}

	var result ZDNSResult
	if err := json.Unmarshal(out, &result); err != nil {
		storeResult(time.Now().Format(time.RFC3339), domain, "None")
		return
	}

	if result.Results.A.Status != "NOERROR" {
		storeResult(result.Results.A.Timestamp, domain, "None")
		return
	}

	if len(result.Results.A.Data.Answers) > 0 {
		for _, answer := range result.Results.A.Data.Answers {
			if answer.Type == "A" {
				storeResult(result.Results.A.Timestamp, domain, answer.Address)
			}
		}
	} else {
		storeResult(result.Results.A.Timestamp, domain, "None")
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

// Worker function to process messages
func worker(id int, jobs <-chan *nsq.Message, wg *sync.WaitGroup) {
	defer wg.Done()
	for msg := range jobs {
		domain := string(msg.Body)
		handleDomain(domain)
		msg.Finish()
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
	numWorkers := 200

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
