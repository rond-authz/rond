// Copyright 2021 Mia srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongoclient

import (
	"context"
	"fmt"
	"time"

	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

// type IMongoClient interface {
// 	Collection(collectionName string) *mongo.Collection
// 	Disconnect() error
// }

type MongoClient struct {
	client       *mongo.Client
	databaseName string
}

const STATE string = "__STATE__"
const PUBLIC string = "PUBLIC"

type ConnectionOpts struct {
	MaxIdleTimeMs int
}

// NewMongoClient tries to setup a new MongoClient instance.
// The function returns a `nil` client if the environment variable `MongoDBUrl` is not specified.
func NewMongoClient(logger logging.Logger, mongodbURL string, connectionOptions ConnectionOpts) (types.MongoClient, error) {
	if mongodbURL == "" {
		logger.Info("No MongoDB configuration provided, skipping setup")
		return nil, nil
	}

	logger.Trace("Start MongoDB client set up")

	parsedConnectionString, err := connstring.ParseAndValidate(mongodbURL)
	if err != nil {
		return nil, fmt.Errorf("failed MongoDB connection string validation: %s", err.Error())
	}

	clientOpts := options.Client().ApplyURI(mongodbURL)
	if connectionOptions.MaxIdleTimeMs != 0 {
		clientOpts = clientOpts.SetMaxConnIdleTime(time.Duration(connectionOptions.MaxIdleTimeMs) * time.Millisecond)
	}

	client, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		return nil, fmt.Errorf("error connecting to MongoDB: %s", err.Error())
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("error verifying MongoDB connection: %s", err.Error())
	}

	mongoClient := MongoClient{
		client:       client,
		databaseName: parsedConnectionString.Database,
	}

	logger.Info("MongoDB client set up completed")
	return &mongoClient, nil
}

func (m *MongoClient) Collection(collectionName string) *mongo.Collection {
	if m != nil {
		return m.client.Database(m.databaseName).Collection(collectionName)
	}
	return nil
}

func (mongoClient *MongoClient) Disconnect() error {
	if mongoClient != nil {
		return mongoClient.client.Disconnect(context.Background())
	}
	return nil
}
