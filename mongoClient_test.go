package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"gotest.tools/v3/assert"
)

const localhostMongoDB = "localhost:27017"

func TestMongoCollectionInjectorMiddleware(t *testing.T) {
	testCollections := &MongoClient{}

	t.Run(`Context gets updated`, func(t *testing.T) {
		invoked := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			collection, ok := r.Context().Value(MongoClientContextKey{}).(*MongoClient)
			assert.Assert(t, ok, "Collection not found")
			assert.Equal(t, collection, testCollections)

			w.WriteHeader(http.StatusOK)
		})

		middleware := mongoCollectionInjectorMiddleware(testCollections)
		builtMiddleware := middleware(next)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		builtMiddleware.ServeHTTP(w, r)

		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code")
		assert.Assert(t, invoked, "Next middleware not invoked")
	})
}

func TestGetMongoCollectionFromContext(t *testing.T) {
	t.Run(`config not found in context`, func(t *testing.T) {
		ctx := context.Background()
		config, err := getMongoCollectionFromContext(ctx)
		assert.Assert(t, config == nil)
		assert.NilError(t, err, "no error expected")
	})

	t.Run(`config found in context`, func(t *testing.T) {
		testCollections := MongoClient{}
		ctx := context.WithValue(context.Background(), MongoClientContextKey{}, testCollections)
		foundConfig, _ := getMongoCollectionFromContext(ctx)
		assert.Equal(t, testCollections, *foundConfig)
	})
}

func TestSetupMongoCollection(t *testing.T) {
	t.Run("if MongoDBUrl empty, returns nil", func(t *testing.T) {
		env := EnvironmentVariables{}
		log, _ := test.NewNullLogger()
		adapter, _ := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "MongoDBUrl is not nil")
	})

	t.Run("if BindingsDatabaseName empty, returns error", func(t *testing.T) {
		env := EnvironmentVariables{
			MongoDBUrl:             "MONGODB_URL",
			RolesCollectionName:    "something new",
			RolesDatabaseName:      "A name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "BindingsDatabaseName is not nil")
		assert.ErrorContains(t, err, `MongoDB url is not empty, RolesDatabaseName: "A name", RolesCollectionName: "something new",  BindingsCollectionName: "Some different name",  BindingsDatabaseName: ""`)
	})

	t.Run("if RolesCollectionName empty, returns error", func(t *testing.T) {
		env := EnvironmentVariables{
			MongoDBUrl:             "MONGODB_URL",
			RolesDatabaseName:      "A name",
			BindingsDatabaseName:   "Another name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "RolesCollectionName collection is not nil")
		assert.ErrorContains(t, err, `MongoDB url is not empty, RolesDatabaseName: "A name", RolesCollectionName: "",  BindingsCollectionName: "Some different name",  BindingsDatabaseName: "Another name"`)
	})

	t.Run("throws if mongo url is without protocol", func(t *testing.T) {
		mongoHost := "not-valid-mongo-url"

		env := EnvironmentVariables{
			MongoDBUrl:             mongoHost,
			RolesCollectionName:    "something new",
			RolesDatabaseName:      "A name",
			BindingsDatabaseName:   "Another name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, err != nil, "setup mongo not returns error")
		assert.ErrorContains(t, err, "error connecting to MongoDB")
		assert.Assert(t, adapter == nil)
	})

	t.Run("throws if mongo url is not correct", func(t *testing.T) {
		mongoHost := "mongodb://not-valid-mongo-url"

		env := EnvironmentVariables{
			MongoDBUrl:             mongoHost,
			RolesCollectionName:    "something new",
			RolesDatabaseName:      "A name",
			BindingsDatabaseName:   "Another name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, err != nil, "setup mongo not returns error")
		assert.ErrorContains(t, err, "error verifying MongoDB connection")
		assert.Assert(t, adapter == nil)
	})

	t.Run("correctly returns mongodb collection", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = localhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s", mongoHost),
			RolesCollectionName:    "roles",
			RolesDatabaseName:      "testdbA",
			BindingsDatabaseName:   "testdbB",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := newMongoClient(env, log)

		defer mongoClient.disconnectMongoClient()
		assert.Assert(t, err == nil, "setup mongo returns error")
		assert.Assert(t, mongoClient != nil)
	})
}
