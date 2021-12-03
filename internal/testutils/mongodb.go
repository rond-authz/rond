/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http/httptest"
	"os"
	"rbac-service/internal/types"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gotest.tools/v3/assert"
)

const LocalhostMongoDB = "localhost:27017"

func GetRandomName(n uint) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// GetAndDisposeTestCollection returns a collection from a random database.
// The function performs test clean up by dropping the database and closing MongoDB client connection.
func GetAndDisposeTestClientsAndCollections(t *testing.T) (*mongo.Client, *mongo.Collection, *mongo.Collection) {
	t.Helper()

	client := GetMongoClient(t)
	db, rolesCollection, bindingsCollection := GetDBAndCollections(t, client)

	t.Cleanup(func() {
		// This sleep has been added to avoid mongo race condition
		time.Sleep(100 * time.Millisecond)
		db.Drop(context.Background())
		client.Disconnect(context.Background())
	})

	return client, rolesCollection, bindingsCollection
}

// GetMongoClient returns a mongodb client. The function does not perform any cleanup, you have to
// manually disconnect from the client.
func GetMongoClient(t *testing.T) *mongo.Client {
	t.Helper()
	// Getting MongoHost in CI from standard environment variable.
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
	client, err := mongo.Connect(context.Background(), clientOpts)
	assert.Assert(t, err == nil, "failed mongo db connection")

	return client
}

// GetDBAndCollections returns a random database and collection.
// The function does not perform any cleanup, you have to
// manually disconnect from the client.
func GetDBAndCollections(t *testing.T, client *mongo.Client) (*mongo.Database, *mongo.Collection, *mongo.Collection) {
	dbName := GetRandomName(10)
	db := client.Database(dbName)
	return db, db.Collection("roles"), db.Collection("bindings")
}

func AssertResponseError(t *testing.T, resp *httptest.ResponseRecorder, statusCode int, errMsg string) {
	t.Helper()
	respBodyBuff, err := ioutil.ReadAll(resp.Body)
	assert.Equal(t, err, nil, "Unexpected error in the response body")

	var respBody types.RequestError
	err = json.Unmarshal(respBodyBuff, &respBody)
	assert.Equal(t, err, nil, "Unexpected error during unmarshalling of the response body")

	assert.Equal(t, respBody.StatusCode, statusCode, "Unexpected status code")

	if errMsg != "" {
		assert.Equal(t, respBody.Message, errMsg, "Unexpected error message")
	}
}
