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

	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/sdk/inputuser"
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

type Config struct {
	RolesCollectionName    string
	BindingsCollectionName string
}

// NewMongoClient creates the struct for accessing user bindings
func NewMongoClient(logger logging.Logger, client *mongoclient.MongoClient, config Config) (inputuser.Client, error) {
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

func (mongoClient *MongoClient) RetrieveUserBindings(ctx context.Context, user types.User) ([]types.Binding, error) {
	if mongoClient == nil {
		return nil, fmt.Errorf("mongoClient is not defined")
	}
	if user.ID == "" {
		return nil, fmt.Errorf("user id is required to fetch bindings")
	}

	userBindingsOrFilter := []bson.M{
		{"subjects": bson.M{"$elemMatch": bson.M{"$eq": user.ID}}},
	}

	if user.Groups != nil {
		userBindingsOrFilter = append(userBindingsOrFilter, bson.M{
			"groups": bson.M{"$elemMatch": bson.M{"$in": user.Groups}},
		})
	}

	filter := bson.M{
		"$and": []bson.M{
			{
				"$or": userBindingsOrFilter,
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

func (mongoClient *MongoClient) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	if mongoClient == nil {
		return nil, fmt.Errorf("mongoClient is not defined")
	}

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
