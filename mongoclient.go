package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// MongoClientContextKey is the context key that shall be used to save
// mongo Collection reference in request contexts.
type MongoClientContextKey struct{}

type MongoClient struct {
	bindings *mongo.Collection
	roles    *mongo.Collection
	client   *mongo.Client
}

// MongoCollectionInjectorMiddleware will inject into request context the
// mongo collections.
func MongoCollectionsInjectorMiddleware(collections *MongoClient) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), MongoClientContextKey{}, collections)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetMongoCollectionFromContext extracts mongo collections adapter struct from
// provided context.
func GetMongoCollectionsFromContext(ctx context.Context) (*MongoClient, error) {
	collectionInterface := ctx.Value(MongoClientContextKey{})
	if collectionInterface == nil {
		return nil, nil
	}

	collections, ok := collectionInterface.(MongoClient)
	if !ok {
		return nil, fmt.Errorf("no MongoDB collection found in context")
	}
	return &collections, nil
}

func (mongoClient *MongoClient) Disconnect() {
	if mongoClient != nil {
		mongoClient.client.Disconnect(context.Background())
	}
}

func newMongoClient(env EnvironmentVariables, logger *logrus.Logger) (*MongoClient, error) {
	if env.MongoDBUrl == "" {
		return nil, nil
	}
	if env.MongoDatabaseName == "" || env.RolesCollectionName == "" || env.BindingsCollectionName == "" {
		return nil, fmt.Errorf(
			`MongoDB url is not empty, MongoDbName: "%s", BindingsCollectionName: "%s",  RolesCollectionName: "%s"`,
			env.MongoDatabaseName,
			env.BindingsCollectionName,
			env.RolesCollectionName,
		)
	}

	clientOpts := options.Client().ApplyURI(env.MongoDBUrl)
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
		client:   client,
		roles:    client.Database(env.MongoDatabaseName).Collection(env.RolesCollectionName),
		bindings: client.Database(env.MongoDatabaseName).Collection(env.BindingsCollectionName),
	}
	return &mongoClient, nil
}
