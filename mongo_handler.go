package ssl_mongo_project

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoClient          *mongo.Client
	certstreamCollection *mongo.Collection
	zdnsCollection       *mongo.Collection
)

func InitMongoDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	mongoClient = client
	certstreamCollection = client.Database("ssl_project").Collection("certstream_results")
	zdnsCollection = client.Database("ssl_project").Collection("zdns_results")
}

func StoreCertstreamResult(certData map[string]interface{}) {
	_, err := certstreamCollection.InsertOne(context.Background(), certData)
	log.Printf("Storing certData: %v", certData)

	if err != nil {
		log.Printf("Failed to insert into MongoDB: %s", err)
	}
}

func StoreZDNSResult(timestamp, domain, ip string, record_ID string) {
	_, err := zdnsCollection.InsertOne(context.Background(), map[string]interface{}{
		"record_ID": record_ID,
		"timestamp": timestamp,
		"domain":    domain,
		"ip":        ip,
	})
	if err != nil {
		log.Printf("Failed to insert into MongoDB: %s", err)
	}
}
