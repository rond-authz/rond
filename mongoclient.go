package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"rbac-service/internal/types"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type MongoClient struct {
	bindings *mongo.Collection
	roles    *mongo.Collection
	client   *mongo.Client
}

const STATE string = "__STATE__"
const PUBLIC string = "PUBLIC"

// MongoClientInjectorMiddleware will inject into request context the
// mongo collections.
func MongoClientInjectorMiddleware(collections types.IMongoClient) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), types.MongoClientContextKey{}, collections)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetMongoClientFromContext extracts mongo collections adapter struct from
// provided context.
func GetMongoClientFromContext(ctx context.Context) (types.IMongoClient, error) {
	collectionInterface := ctx.Value(types.MongoClientContextKey{})

	if collectionInterface == nil {
		return nil, nil
	}
	collections, ok := collectionInterface.(types.IMongoClient)
	if !ok {
		return nil, fmt.Errorf("no MongoDB collection found in context")
	}
	return collections, nil
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
	if env.RolesCollectionName == "" || env.BindingsCollectionName == "" {
		return nil, fmt.Errorf(
			`MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "%s",  RolesCollectionName: "%s"`,
			env.BindingsCollectionName,
			env.RolesCollectionName,
		)
	}

	parsedConnectionString, err := connstring.ParseAndValidate(env.MongoDBUrl)
	if err != nil {
		return nil, fmt.Errorf("failed MongoDB connection string validation: %s", err.Error())
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
		roles:    client.Database(parsedConnectionString.Database).Collection(env.RolesCollectionName),
		bindings: client.Database(parsedConnectionString.Database).Collection(env.BindingsCollectionName),
	}
	return &mongoClient, nil
}

func (mongoClient *MongoClient) RetrieveUserBindings(ctx context.Context, user *types.User) ([]types.Binding, error) {
	filter := bson.M{
		"$and": []bson.M{
			{
				"$or": []bson.M{
					{"subjects": bson.M{"$elemMatch": bson.M{"$eq": user.UserID}}},
					{"groups": bson.M{"$elemMatch": bson.M{"$in": user.UserGroups}}},
				},
			},
			{STATE: PUBLIC},
		},
	}
	cursor, err := mongoClient.bindings.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	bindingsResult := make([]types.Binding, 0)
	if err = cursor.All(ctx, &bindingsResult); err != nil {
		return nil, err
	}
	return bindingsResult, nil
}

func (mongoClient *MongoClient) RetrieveRoles(ctx context.Context) ([]types.Role, error) {
	filter := bson.M{
		STATE: PUBLIC,
	}
	cursor, err := mongoClient.roles.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	rolesResult := make([]types.Role, 0)
	if err = cursor.All(ctx, &rolesResult); err != nil {
		return nil, err
	}
	return rolesResult, nil
}

func (mongoClient *MongoClient) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	filter := bson.M{
		"$and": []bson.M{
			{
				"roleId": bson.M{"$in": userRolesId},
			},
			{STATE: PUBLIC},
		},
	}
	cursor, err := mongoClient.roles.Find(
		ctx,
		filter,
	)
	if err != nil {
		return nil, err
	}
	rolesResult := make([]types.Role, 0)
	if err = cursor.All(ctx, &rolesResult); err != nil {
		return nil, err
	}
	return rolesResult, nil
}
