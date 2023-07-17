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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/logger"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

type MongoClient struct {
	client       *mongo.Client
	bindings     *mongo.Collection
	roles        *mongo.Collection
	databaseName string
}

const STATE string = "__STATE__"
const PUBLIC string = "PUBLIC"

// MongoClientInjectorMiddleware will inject into request context the
// mongo collections.
func MongoClientInjectorMiddleware(collections types.IMongoClient) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithMongoClient(r.Context(), collections)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func WithMongoClient(ctx context.Context, mongoClient types.IMongoClient) context.Context {
	return context.WithValue(ctx, types.MongoClientContextKey{}, mongoClient)
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

func (mongoClient *MongoClient) Disconnect() error {
	if mongoClient != nil {
		return mongoClient.client.Disconnect(context.Background())
	}
	return nil
}

// NewMongoClient tries to setup a new MongoClient instance.
// The function returns a `nil` client if the environment variable `MongoDBUrl` is not specified.
func NewMongoClient(env config.EnvironmentVariables, logger logger.Logger) (*MongoClient, error) {
	if env.MongoDBUrl == "" {
		logger.Info("No MongoDB configuration provided, skipping setup")
		return nil, nil
	}

	logger.Trace("Start MongoDB client set up")
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
		client:       client,
		databaseName: parsedConnectionString.Database,
		roles:        client.Database(parsedConnectionString.Database).Collection(env.RolesCollectionName),
		bindings:     client.Database(parsedConnectionString.Database).Collection(env.BindingsCollectionName),
	}

	logger.Info("MongoDB client set up completed")
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

func (mongoClient *MongoClient) FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error) {
	collection := mongoClient.client.Database(mongoClient.databaseName).Collection(collectionName)
	log := logger.FromContext(ctx)
	log.WithFields(map[string]any{
		"mongoQuery":     query,
		"dbName":         mongoClient.databaseName,
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
	collection := mongoClient.client.Database(mongoClient.databaseName).Collection(collectionName)
	log := logger.FromContext(ctx)
	log.WithFields(map[string]any{
		"mongoQuery":     query,
		"dbName":         mongoClient.databaseName,
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

func RolesIDsFromBindings(bindings []types.Binding) []string {
	rolesIds := []string{}
	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if !utils.Contains(rolesIds, role) {
				rolesIds = append(rolesIds, role)
			}
		}
	}
	return rolesIds
}

func RetrieveUserBindingsAndRoles(logger logger.Logger, req *http.Request, userHeaders types.UserHeadersKeys) (types.User, error) {
	requestContext := req.Context()
	mongoClient, err := GetMongoClientFromContext(requestContext)
	if err != nil {
		return types.User{}, fmt.Errorf("unexpected error retrieving MongoDB Client from request context")
	}

	var user types.User

	user.UserGroups = strings.Split(req.Header.Get(userHeaders.GroupsHeaderKey), ",")
	user.UserID = req.Header.Get(userHeaders.IDHeaderKey)

	userProperties := make(map[string]interface{})
	_, err = utils.UnmarshalHeader(req.Header, userHeaders.PropertiesHeaderKey, &userProperties)
	if err != nil {
		return types.User{}, fmt.Errorf("user properties header is not valid: %s", err.Error())
	}
	user.Properties = userProperties

	if mongoClient != nil && user.UserID != "" {
		user.UserBindings, err = mongoClient.RetrieveUserBindings(requestContext, &user)
		if err != nil {
			logger.WithField("error", map[string]any{"message": err.Error()}).Error("something went wrong while retrieving user bindings")
			return types.User{}, fmt.Errorf("error while retrieving user bindings: %s", err.Error())
		}

		userRolesIds := RolesIDsFromBindings(user.UserBindings)
		user.UserRoles, err = mongoClient.RetrieveUserRolesByRolesID(requestContext, userRolesIds)
		if err != nil {
			logger.WithField("error", map[string]any{"message": err.Error()}).Error("something went wrong while retrieving user roles")

			return types.User{}, fmt.Errorf("error while retrieving user Roles: %s", err.Error())
		}
		logger.WithFields(map[string]any{
			"foundBindingsLength": len(user.UserBindings),
			"foundRolesLength":    len(user.UserRoles),
		}).Trace("found bindings and roles")
	}
	return user, nil
}
