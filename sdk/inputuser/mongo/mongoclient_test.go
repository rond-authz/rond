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
	"os"
	"reflect"
	"testing"

	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/stretchr/testify/require"
)

func TestSetupMongoCollection(t *testing.T) {
	log := logging.NewNoOpLogger()

	t.Run("if RolesCollectionName empty, returns error", func(t *testing.T) {
		mongoDBURL, _, _, _ := getMongoDBURL(t)
		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)

		config := Config{
			BindingsCollectionName: "Some different name",
		}
		adapter, err := NewMongoClient(log, client, config)

		require.Nil(t, adapter, "RolesCollectionName collection is not nil")
		require.EqualError(t, err, `MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "Some different name",  RolesCollectionName: ""`)
	})

	t.Run("correctly returns mongodb client", func(t *testing.T) {
		mongoDBURL, _, _, _ := getMongoDBURL(t)
		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)

		config := Config{
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		mongoClient, err := NewMongoClient(log, client, config)

		defer mongoClient.Disconnect()
		require.True(t, err == nil, "setup mongo returns error")
		require.True(t, mongoClient != nil)
	})
}

func TestMongoCollections(t *testing.T) {
	log := logging.NewNoOpLogger()

	t.Run("testing retrieve user bindings from mongo", func(t *testing.T) {
		mongoDBURL, _, rolesCollection, bindingsCollection := getMongoDBURL(t)
		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)

		config := Config{
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, client, config)
		require.NoError(t, err)
		defer mongoClient.Disconnect()

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveUserBindings(ctx, types.User{ID: "user1", Groups: []string{"group1", "group2"}})
		expected := []types.Binding{
			{
				BindingID:         "binding1",
				Subjects:          []string{"user1"},
				Roles:             []string{"role1", "role2"},
				Groups:            []string{"group1"},
				Permissions:       []string{"permission4"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding2",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group4"},
				Permissions:       []string{"permission7"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding3",
				Subjects:          []string{"user5"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group2"},
				Permissions:       []string{"permission10", "permission4"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding4",
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group2"},
				Permissions:       []string{"permission11"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "bindingForRowFiltering",
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group1"},
				Permissions:       []string{"console.project.view"},
				Resource:          &types.Resource{ResourceType: "custom", ResourceID: "9876"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "bindingForRowFilteringFromSubject",
				Subjects:          []string{"filter_test"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group1"},
				Permissions:       []string{"console.project.view"},
				Resource:          &types.Resource{ResourceType: "custom", ResourceID: "12345"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding5",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Permissions:       []string{"permission12"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		require.True(t, reflect.DeepEqual(result, expected),
			"Error while getting permissions")
	})

	t.Run("testing retrieve user bindings from mongo - user without groups", func(t *testing.T) {
		mongoDBURL, _, rolesCollection, bindingsCollection := getMongoDBURL(t)
		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)

		config := Config{
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, client, config)
		require.NoError(t, err)
		defer mongoClient.Disconnect()

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, err := mongoClient.RetrieveUserBindings(ctx, types.User{ID: "user1"})
		expected := []types.Binding{
			{
				BindingID:         "binding1",
				Subjects:          []string{"user1"},
				Roles:             []string{"role1", "role2"},
				Groups:            []string{"group1"},
				Permissions:       []string{"permission4"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding2",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group4"},
				Permissions:       []string{"permission7"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding5",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Permissions:       []string{"permission12"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		require.NoError(t, err)
		require.Equal(t, result, expected, "Error while getting permissions")
	})

	t.Run("testing retrieve user bindings from mongo - no userId passed", func(t *testing.T) {
		mongoDBURL, _, rolesCollection, bindingsCollection := getMongoDBURL(t)
		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)
		config := Config{
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, client, config)
		require.NoError(t, err)
		defer mongoClient.Disconnect()

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		_, err = mongoClient.RetrieveUserBindings(ctx, types.User{})
		require.EqualError(t, err, "user id is required to fetch bindings")
	})

	t.Run("retrieve all roles by id from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		_, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		mongoDBURL := fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName)

		client, err := mongoclient.NewMongoClient(log, mongoDBURL)
		require.NoError(t, err)

		config := Config{
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}
		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, client, config)
		defer mongoClient.Disconnect()
		require.NoError(t, err, "setup mongo returns error")

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveUserRolesByRolesID(ctx, []string{"role1", "role3", "notExistingRole"})
		expected := []types.Role{
			{
				RoleID:            "role1",
				RoleName:          "Role1",
				Permissions:       []string{"permission1", "permission2", "foobar"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "role3",
				RoleName:          "Role3",
				Permissions:       []string{"permission3", "permission5", "console.project.view"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		require.True(t, reflect.DeepEqual(result, expected),
			"Error while getting permissions")
	})
}

func TestMongoClientNil(t *testing.T) {
	var mongoClient *MongoClient

	t.Run("retrieve user bindings", func(t *testing.T) {
		_, err := mongoClient.RetrieveUserBindings(context.Background(), types.User{})
		require.EqualError(t, err, "mongoClient is not defined")
	})

	t.Run("retrieve roles by roleIds", func(t *testing.T) {
		_, err := mongoClient.RetrieveUserRolesByRolesID(context.Background(), []string{"id"})
		require.EqualError(t, err, "mongoClient is not defined")
	})
}

func getMongoDBURL(t *testing.T) (
	mongoDBURL string, dbName string, rolesCollection *mongo.Collection, bindingsCollection *mongo.Collection) {
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	_, dbName, rolesCollection, bindingsCollection = testutils.GetAndDisposeTestClientsAndCollections(t)
	mongoDBURL = fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName)
	return
}
