package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"rbac-service/internal/types"
	"rbac-service/internal/utils"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
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

func (mongoClient *MongoClient) FindUserPermissions(ctx context.Context, user *types.User) ([]string, error) {
	var userPermissions []string

	roles, err := findUserPermissionsAndRolesFromBindings(ctx, &userPermissions, mongoClient.bindings, user)
	if err != nil {
		return nil, fmt.Errorf("error retrieving bindings from collection: %s", err.Error())
	}

	if len(roles) == 0 {
		return userPermissions, nil
	}

	if err = findRolePermissions(ctx, &userPermissions, mongoClient.roles, roles); err != nil {
		return nil, fmt.Errorf("error retrieving permissions from roles collection: %s", err.Error())
	}

	return userPermissions, nil
}

func findRolePermissions(ctx context.Context, userPermissions *[]string, rolesCollection *mongo.Collection, roles []string) error {
	filter := bson.M{
		"$and": []bson.M{
			{"roleId": bson.M{"$in": roles}},
			{STATE: PUBLIC},
		},
	}

	options := options.Find().SetProjection(bson.M{"_id": 0, "permissions": 1})
	cursor, err := rolesCollection.Find(
		ctx,
		filter,
		options,
	)
	if err != nil {
		return err
	}
	rolesResult := make([]types.Role, 0)
	if err = cursor.All(ctx, &rolesResult); err != nil {
		return err
	}

	for _, role := range rolesResult {
		permissions := role.Permissions
		for _, permission := range permissions {
			utils.AppendUnique(*&userPermissions, permission)
		}
	}
	return nil
}

func findUserPermissionsAndRolesFromBindings(ctx context.Context, userPermissions *[]string, bindingsCollection *mongo.Collection, user *types.User) ([]string, error) {
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
	options := options.Find().SetProjection(
		bson.M{"_id": 0, "bindingId": 1, "permissions": 1, "roles": 1},
	)
	cursor, err := bindingsCollection.Find(
		ctx,
		filter,
		options,
	)
	if err != nil {
		return nil, err
	}

	var bindingsResult []types.Binding
	if err = cursor.All(ctx, &bindingsResult); err != nil {
		return nil, err
	}
	roles := make([]string, 0)
	for _, binding := range bindingsResult {
		bindingPermissions := binding.Permissions
		for _, bindingpermission := range bindingPermissions {
			utils.AppendUnique(userPermissions, bindingpermission)
		}
		bindingRoles := binding.Roles
		for _, bindingRole := range bindingRoles {
			utils.AppendUnique(&roles, bindingRole)
		}
	}
	return roles, nil
}
