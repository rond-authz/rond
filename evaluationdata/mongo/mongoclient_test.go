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
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/rond-authz/rond/evaluationdata"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"
	"github.com/stretchr/testify/require"
)

func TestSetupMongoCollection(t *testing.T) {
	t.Run("if MongoDBUrl empty, returns nil", func(t *testing.T) {
		log := logging.NewNoOpLogger()
		adapter, _ := NewMongoClient(log, Config{})
		require.Nil(t, adapter, "MongoDBUrl is not nil")
	})

	t.Run("if RolesCollectionName empty, returns error", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		config := Config{
			MongoDBURL:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			BindingsCollectionName: "Some different name",
		}
		log := logging.NewNoOpLogger()
		adapter, err := NewMongoClient(log, config)
		require.Nil(t, adapter, "RolesCollectionName collection is not nil")
		require.EqualError(t, err, `MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "Some different name",  RolesCollectionName: ""`)
	})

	t.Run("throws if mongo url is without protocol", func(t *testing.T) {
		mongoHost := "not-valid-mongo-url"

		config := Config{
			MongoDBURL:             mongoHost,
			RolesCollectionName:    "something new",
			BindingsCollectionName: "Some different name",
		}
		log := logging.NewNoOpLogger()
		adapter, err := NewMongoClient(log, config)
		require.True(t, err != nil, "setup mongo not returns error")
		require.Contains(t, err.Error(), "failed MongoDB connection string validation:")
		require.True(t, adapter == nil)
	})

	t.Run("correctly returns mongodb client", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		config := Config{
			MongoDBURL:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, config)

		defer mongoClient.Disconnect()
		require.True(t, err == nil, "setup mongo returns error")
		require.True(t, mongoClient != nil)
	})
}

func TestMongoCollections(t *testing.T) {
	t.Run("testing retrieve user bindings from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		_, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		config := Config{
			MongoDBURL:             fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, config)
		require.NoError(t, err)
		defer mongoClient.Disconnect()

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveUserBindings(ctx, &types.User{UserID: "user1", UserGroups: []string{"group1", "group2"}})
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

	t.Run("retrieve all roles from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		_, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)

		config := Config{
			MongoDBURL:             fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}
		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, config)
		defer mongoClient.Disconnect()
		require.NoError(t, err, "setup mongo returns error")

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveRoles(ctx)
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
			{
				RoleID:            "notUsedByAnyone",
				RoleName:          "Not Used By Anyone",
				Permissions:       []string{"permissionNotUsed1", "permissionNotUsed2"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		require.True(t, reflect.DeepEqual(result, expected), "Error while getting permissions")
	})

	t.Run("retrieve all roles by id from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		_, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)

		config := Config{
			MongoDBURL:             fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}
		log := logging.NewNoOpLogger()
		mongoClient, err := NewMongoClient(log, config)
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

func TestRolesIDSFromBindings(t *testing.T) {
	t.Run("retrieve roles ids #1", func(t *testing.T) {
		result := RolesIDsFromBindings([]types.Binding{
			{Roles: []string{"a", "b"}},
			{Roles: []string{"a", "b"}},
			{Roles: []string{"c", "d"}},
			{Roles: []string{"e"}},
		})

		require.Equal(t, []string{"a", "b", "c", "d", "e"}, result)
	})

	t.Run("retrieve roles ids #2", func(t *testing.T) {
		bindings := []types.Binding{
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
				BindingID:         "binding5",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Permissions:       []string{"permission12"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		rolesIds := RolesIDsFromBindings(bindings)
		expected := []string{"role1", "role2", "role3", "role4"}
		require.True(t, reflect.DeepEqual(rolesIds, expected), "Error while getting permissions")
	})
}

func TestRetrieveUserBindingsAndRoles(t *testing.T) {
	log := logging.NewNoOpLogger()
	userHeaders := types.UserHeadersKeys{
		GroupsHeaderKey:     "thegroupsheader",
		IDHeaderKey:         "theuserheader",
		PropertiesHeaderKey: "userproperties",
	}

	t.Run("extract user from request without querying MongoDB", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		user, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.NoError(t, err)
		require.Equal(t, types.User{
			UserID:     "userId",
			UserGroups: []string{"group1", "group2"},
			Properties: map[string]interface{}{},
		}, user)
	})

	t.Run("extract user with no id in headers does not perform queries", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(evaluationdata.WithClient(req.Context(), mock))

		_, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.NoError(t, err)
	})

	t.Run("extract user but retrieve bindings fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(evaluationdata.WithClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		_, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.Error(t, err, "Error while retrieving user bindings: some error")
	})

	t.Run("extract user bindings but retrieve roles by role id fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
			},
			UserRolesError: fmt.Errorf("some error 2"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(evaluationdata.WithClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		_, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.Error(t, err, "Error while retrieving user Roles: some error 2")
	})

	t.Run("extract user bindings and roles", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
				{Roles: []string{"r3"}},
			},
			UserRoles: []types.Role{
				{RoleID: "r1", Permissions: []string{"p1", "p2"}},
				{RoleID: "r2", Permissions: []string{"p3", "p4"}},
				{RoleID: "r3", Permissions: []string{"p5"}},
			},
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(evaluationdata.WithClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		user, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.NoError(t, err)
		require.Equal(t, types.User{
			UserID:     "userId",
			UserGroups: []string{"group1", "group2"},
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
				{Roles: []string{"r3"}},
			},
			UserRoles: []types.Role{
				{RoleID: "r1", Permissions: []string{"p1", "p2"}},
				{RoleID: "r2", Permissions: []string{"p3", "p4"}},
				{RoleID: "r3", Permissions: []string{"p5"}},
			},
			Properties: map[string]interface{}{},
		}, user)
	})

	t.Run("allow empty userproperties header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("userproperties", "")
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		user, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.NoError(t, err)
		require.Equal(t, types.User{
			UserID:     "userId",
			UserGroups: []string{"group1", "group2"},
			Properties: map[string]interface{}{},
		}, user)
	})

	t.Run("fail on invalid userproperties header value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("userproperties", "1")

		_, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
		require.ErrorContains(t, err, "user properties header is not valid:")
	})
}
