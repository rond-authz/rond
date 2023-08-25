package custom_builtins

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/stretchr/testify/require"
)

func TestNewMongoClient(t *testing.T) {
	t.Run("return nil client if mongodb url not passed", func(t *testing.T) {
		client, err := NewMongoClient(logging.NewNoOpLogger(), "")
		require.NoError(t, err)
		require.Nil(t, client)
	})

	t.Run("fails if mongo url is wrong", func(t *testing.T) {
		client, err := NewMongoClient(logging.NewNoOpLogger(), "wrong-url")
		require.EqualError(t, err, "failed MongoDB connection string validation: error parsing uri: scheme must be \"mongodb\" or \"mongodb+srv\"")
		require.Nil(t, client)
	})
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
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	dbName := testutils.GetRandomName(10)
	log := logging.NewNoOpLogger()
	mongoClient, err := NewMongoClient(log, fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName))
	require.NoError(t, err)
	defer mongoClient.Disconnect()
	require.True(t, err == nil, "setup mongo returns error")

	collectionName := "my-collection"
	populateCollection(t, dbName, collectionName)

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
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	dbName := testutils.GetRandomName(10)
	log := logging.NewNoOpLogger()
	mongoClient, err := NewMongoClient(log, fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName))
	require.NoError(t, err)
	defer mongoClient.Disconnect()
	require.True(t, err == nil, "setup mongo returns error")

	collectionName := "my-collection"
	populateCollection(t, dbName, collectionName)

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

func populateCollection(t *testing.T, dbName string, collectionName string) {
	t.Helper()

	client := testutils.GetMongoClient(t)
	ctx := context.Background()

	db := client.Database(dbName)
	collection := db.Collection(collectionName)
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
		db.Drop(ctx)
	})
}
