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
	"fmt"
	"os"
	"testing"

	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestNewMongoClient(t *testing.T) {
	log := logging.NewNoOpLogger()

	mongoDBURL, _ := getMongoDBURL(t)
	mongoClient, err := mongoclient.NewMongoClient(log, mongoDBURL, mongoclient.ConnectionOpts{})
	require.NoError(t, err)

	client, err := NewMongoClient(logging.NewNoOpLogger(), mongoClient)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestGetMongoCollectionFromContext(t *testing.T) {
	t.Run(`config not found in context`, func(t *testing.T) {
		ctx := context.Background()
		config, err := GetMongoClientFromContext(ctx)
		require.True(t, config == nil)
		require.NoError(t, err, "no error expected")
	})

	t.Run(`config found in context`, func(t *testing.T) {
		testClient := &MongoClient{}
		ctx := WithMongoClient(context.Background(), testClient)
		foundConfig, err := GetMongoClientFromContext(ctx)
		require.NoError(t, err, "unexpected error")
		require.True(t, foundConfig != nil)
	})

	t.Run(`throws if client not correctly in context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), mongoClientCustomBuiltinContextKey{}, "")
		foundConfig, err := GetMongoClientFromContext(ctx)
		require.EqualError(t, err, "no MongoDB client found in context")
		require.Nil(t, foundConfig)
	})
}

func TestMongoFindOne(t *testing.T) {
	log := logging.NewNoOpLogger()
	mongoDBURL := testutils.GetMongoDBURL(t)
	client, err := mongoclient.NewMongoClient(log, mongoDBURL, mongoclient.ConnectionOpts{})
	require.NoError(t, err)
	defer client.Disconnect()

	mongoClient, err := NewMongoClient(log, client)
	require.NoError(t, err)

	collectionName := "my-collection"
	populateCollection(t, client.Collection(collectionName))

	t.Run("finds a document", func(t *testing.T) {
		result, err := mongoClient.FindOne(context.Background(), collectionName, map[string]interface{}{
			"id": "my-id-1",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		resultMap := result.(map[string]interface{})
		require.True(t, resultMap["_id"] != nil)

		delete(resultMap, "_id")
		require.Equal(t, map[string]interface{}{
			"some": "field",
			"id":   "my-id-1",
			"nested": map[string]interface{}{
				"some": "think",
			},
			"array": []interface{}{"some", "value"},
		}, result)
	})

	t.Run("does not find a document", func(t *testing.T) {
		result, err := mongoClient.FindOne(context.Background(), collectionName, map[string]interface{}{
			"key": 42,
		})
		require.NoError(t, err)
		require.True(t, result == nil)
	})
}

func TestMongoFindMany(t *testing.T) {
	log := logging.NewNoOpLogger()
	client, dbName := testutils.GetAndDisposeMongoClient(t)

	clientWrapper := &testutils.MockMongoClient{ActualClient: client, DBName: dbName}
	mongoClient, err := NewMongoClient(log, clientWrapper)
	require.NoError(t, err)

	collectionName := "my-collection"
	populateCollection(t, client.Database(dbName).Collection(collectionName))

	t.Run("finds multiple documents", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), collectionName, map[string]interface{}{
			"some": "field",
		})
		require.NoError(t, err)

		require.Len(t, result, 2)
		resultMap := result[0].(map[string]interface{})
		require.True(t, resultMap["_id"] != nil)

		delete(resultMap, "_id")
		require.Equal(t, map[string]interface{}{
			"some": "field",
			"id":   "my-id-1",
			"nested": map[string]interface{}{
				"some": "think",
			},
			"array": []interface{}{"some", "value"},
		}, resultMap)

		result1Map := result[1].(map[string]interface{})
		require.True(t, result1Map["_id"] != nil)

		delete(result1Map, "_id")
		require.Equal(t, map[string]interface{}{
			"some": "field",
			"id":   "my-id-2",
		}, result1Map)
	})

	t.Run("does not find any document", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), collectionName, map[string]interface{}{
			"id": "not-exists",
		})
		require.NoError(t, err)
		require.Len(t, result, 0)
	})

	t.Run("returns error on invalid query", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), collectionName, map[string]interface{}{
			"$UNKWNONW": "invalid",
		})
		require.Contains(t, err.Error(), "unknown top level operator")
		require.Len(t, result, 0)
	})
}

func populateCollection(t *testing.T, collection *mongo.Collection) {
	t.Helper()
	ctx := context.Background()

	_, err := collection.DeleteMany(ctx, bson.D{})
	require.NoError(t, err)
	_, err = collection.InsertMany(ctx, []interface{}{
		map[string]any{
			"some": "field",
			"id":   "my-id-1",
			"nested": map[string]string{
				"some": "think",
			},
			"array": []string{"some", "value"},
		},
		map[string]any{
			"some": "field",
			"id":   "my-id-2",
		},
		map[string]any{
			"some": "other",
			"id":   "my-id-3",
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		collection.Drop(ctx)
	})
}

func getMongoDBURL(t *testing.T) (connectionString string, dbName string) {
	t.Helper()
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	dbName = testutils.GetRandomName(10)
	connectionString = fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName)
	return
}
