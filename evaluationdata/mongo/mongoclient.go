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
	"fmt"
	"net/http"
	"strings"

	"github.com/rond-authz/rond/evaluationdata"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoClient struct {
	*mongoclient.MongoClient
	bindings *mongo.Collection
	roles    *mongo.Collection
}

const STATE string = "__STATE__"
const PUBLIC string = "PUBLIC"

func (mongoClient *MongoClient) Disconnect() error {
	if mongoClient != nil {
		return mongoClient.MongoClient.Disconnect()
	}
	return nil
}

type Config struct {
	MongoDBURL string

	RolesCollectionName    string
	BindingsCollectionName string
}

// NewMongoClient tries to setup a new MongoClient instance.
// The function returns a `nil` client if the environment variable `MongoDBUrl` is not specified.
func NewMongoClient(logger logging.Logger, config Config) (*MongoClient, error) {
	client, err := mongoclient.NewMongoClient(logger, config.MongoDBURL)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, nil
	}

	if config.RolesCollectionName == "" || config.BindingsCollectionName == "" {
		return nil, fmt.Errorf(
			`MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "%s",  RolesCollectionName: "%s"`,
			config.BindingsCollectionName,
			config.RolesCollectionName,
		)
	}

	return &MongoClient{
		MongoClient: client,
		roles:       client.Collection(config.RolesCollectionName),
		bindings:    client.Collection(config.BindingsCollectionName),
	}, nil
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

// TODO: move from here
func RetrieveUserBindingsAndRoles(logger logging.Logger, req *http.Request, userHeaders types.UserHeadersKeys) (types.User, error) {
	requestContext := req.Context()
	mongoClient, err := evaluationdata.GetClientFromContext(requestContext)
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
