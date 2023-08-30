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
	"fmt"
	"os"
	"testing"

	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"

	"github.com/stretchr/testify/require"
)

func TestSetupMongoCollection(t *testing.T) {
	t.Run("if MongoDBUrl empty, returns nil", func(t *testing.T) {
		log := logging.NewNoOpLogger()
		adapter, _ := NewMongoClient(log, "")
		require.True(t, adapter == nil, "MongoDBUrl is not nil")
	})

	t.Run("throws if mongo url is without protocol", func(t *testing.T) {
		mongoHost := "not-valid-mongo-url"

		log := logging.NewNoOpLogger()
		adapter, err := NewMongoClient(log, mongoHost)
		require.True(t, err != nil, "setup mongo not returns error")
		require.Contains(t, err.Error(), "failed MongoDB connection string validation:")
		require.True(t, adapter == nil)
	})

	t.Run("correctly returns mongodb client", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, fmt.Sprintf("mongodb://%s/%s", mongoHost, testutils.GetRandomName(10)))

		defer mongoClient.Disconnect()
		require.True(t, err == nil, "setup mongo returns error")
		require.True(t, mongoClient != nil)
	})

	t.Run("correctly returns mongodb collection", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, fmt.Sprintf("mongodb://%s/%s", mongoHost, testutils.GetRandomName(10)))

		collName := "a-collection"
		coll := mongoClient.Collection(collName)
		require.Equal(t, collName, coll.Name())

		defer mongoClient.Disconnect()
		require.True(t, err == nil, "setup mongo returns error")
		require.True(t, mongoClient != nil)
	})

	t.Run("if client is nil", func(t *testing.T) {
		var mongoClient *MongoClient

		require.NoError(t, mongoClient.Disconnect())
		require.Nil(t, mongoClient.Collection("name"))
	})
}
