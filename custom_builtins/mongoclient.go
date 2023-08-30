// Copyright 2023 Mia srl
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

package custom_builtins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/logging"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type IMongoClient interface {
	FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error)
	FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error)
	Disconnect() error
}

type mongoClientCustomBuiltinContextKey struct{}

func WithMongoClient(ctx context.Context, mongoClient IMongoClient) context.Context {
	return context.WithValue(ctx, mongoClientCustomBuiltinContextKey{}, mongoClient)
}

func GetMongoClientFromContext(ctx context.Context) (IMongoClient, error) {
	clientInterface := ctx.Value(mongoClientCustomBuiltinContextKey{})
	if clientInterface == nil {
		return nil, nil
	}

	client, ok := clientInterface.(IMongoClient)
	if !ok {
		return nil, fmt.Errorf("no MongoDB client found in context")
	}
	return client, nil
}

type MongoClient struct {
	client *mongoclient.MongoClient
}

func NewMongoClient(logger logging.Logger, mongodbURL string) (IMongoClient, error) {
	mongoClient, err := mongoclient.NewMongoClient(logger, mongodbURL)
	if err != nil {
		return nil, err
	}
	if mongoClient == nil {
		return nil, nil
	}
	return &MongoClient{
		client: mongoClient,
	}, nil
}

func (mongoClient *MongoClient) FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error) {
	collection := mongoClient.client.Collection(collectionName)
	log := logging.FromContext(ctx)
	log.WithFields(map[string]any{
		"mongoQuery":     query,
		"collectionName": collectionName,
	}).Debug("performing query")

	result := collection.FindOne(ctx, query)

	var bsonDocument bson.D
	err := result.Decode(&bsonDocument)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			log.WithField("error", map[string]any{"message": err.Error()}).Warn("no document found")
			return nil, nil
		}
		log.WithField("error", map[string]any{"message": err.Error()}).Error("failed query decode")
		return nil, err
	}

	temporaryBytes, err := bson.MarshalExtJSON(bsonDocument, true, true)
	if err != nil {
		log.WithField("error", map[string]any{"message": err.Error()}).Error("failed query result marshalling")
		return nil, err
	}

	var res map[string]interface{}
	if err := json.Unmarshal(temporaryBytes, &res); err != nil {
		log.WithField("error", map[string]any{"message": err.Error()}).Error("failed query result deserialization")
		return nil, err
	}
	return res, nil
}

func (mongoClient *MongoClient) FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error) {
	collection := mongoClient.client.Collection(collectionName)
	log := logging.FromContext(ctx)
	log.WithFields(map[string]any{
		"mongoQuery":     query,
		"collectionName": collectionName,
	}).Debug("performing query")

	resultCursor, err := collection.Find(ctx, query)
	if err != nil {
		log.WithField("error", map[string]any{"message": err.Error()}).Error("failed query execution")
		return nil, err
	}

	results := make([]interface{}, 0)
	if err := resultCursor.All(ctx, &results); err != nil {
		log.WithField("error", map[string]any{"message": err.Error()}).Error("failed complete query result deserialization")
		return nil, err
	}

	for i := 0; i < len(results); i++ {
		temporaryBytes, err := bson.MarshalExtJSON(results[i], true, true)
		if err != nil {
			log.WithFields(map[string]any{
				"error":       map[string]any{"message": err.Error()},
				"resultIndex": i,
			}).Error("failed query result marshalling")
			return nil, err
		}
		if err := json.Unmarshal(temporaryBytes, &results[i]); err != nil {
			log.WithFields(map[string]any{
				"error":       map[string]any{"message": err.Error()},
				"resultIndex": i,
			}).Error("failed result document deserialization")
			return nil, err
		}
	}
	return results, nil
}

func (mongoClient *MongoClient) Disconnect() error {
	return mongoClient.client.Disconnect()
}
