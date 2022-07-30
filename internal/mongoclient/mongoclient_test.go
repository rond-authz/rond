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

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"gotest.tools/v3/assert"
)

func TestMongoCollectionInjectorMiddleware(t *testing.T) {
	testCollections := &MongoClient{}

	t.Run(`Context gets updated`, func(t *testing.T) {
		invoked := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			collection, ok := r.Context().Value(types.MongoClientContextKey{}).(*MongoClient)
			assert.Assert(t, ok, "Collection not found")
			assert.Equal(t, collection, testCollections)

			w.WriteHeader(http.StatusOK)
		})

		middleware := MongoClientInjectorMiddleware(testCollections)
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
		config, err := GetMongoClientFromContext(ctx)
		assert.Assert(t, config == nil)
		assert.NilError(t, err, "no error expected")
	})

	t.Run(`config found in context`, func(t *testing.T) {
		testCollections := &MongoClient{}
		ctx := context.WithValue(context.Background(), types.MongoClientContextKey{}, testCollections)
		foundConfig, err := GetMongoClientFromContext(ctx)
		assert.NilError(t, err, "unexpected error")
		assert.Assert(t, foundConfig != nil)
	})
}

func TestSetupMongoCollection(t *testing.T) {
	t.Run("if MongoDBUrl empty, returns nil", func(t *testing.T) {
		env := config.EnvironmentVariables{}
		log, _ := test.NewNullLogger()
		adapter, _ := NewMongoClient(env, log)
		assert.Assert(t, adapter == nil, "MongoDBUrl is not nil")
	})

	t.Run("if RolesCollectionName empty, returns error", func(t *testing.T) {
		env := config.EnvironmentVariables{
			MongoDBUrl:             "MONGODB_URL",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := NewMongoClient(env, log)
		assert.Assert(t, adapter == nil, "RolesCollectionName collection is not nil")
		assert.ErrorContains(t, err, `MongoDB url is not empty, required variables might be missing: BindingsCollectionName: "Some different name",  RolesCollectionName: ""`)
	})

	t.Run("throws if mongo url is without protocol", func(t *testing.T) {
		mongoHost := "not-valid-mongo-url"

		env := config.EnvironmentVariables{
			MongoDBUrl:             mongoHost,
			RolesCollectionName:    "something new",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := NewMongoClient(env, log)
		assert.Assert(t, err != nil, "setup mongo not returns error")
		assert.ErrorContains(t, err, "failed MongoDB connection string validation:")
		assert.Assert(t, adapter == nil)
	})

	t.Run("correctly returns mongodb collection", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := config.EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := NewMongoClient(env, log)

		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		assert.Assert(t, mongoClient != nil)
	})
}

func TestMongoCollections(t *testing.T) {
	t.Run("testing retrieve user bindings from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := config.EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := NewMongoClient(env, log)
		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		client, _, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		mongoClient.client = client
		mongoClient.roles = rolesCollection
		mongoClient.bindings = bindingsCollection

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
		assert.Assert(t, reflect.DeepEqual(result, expected),
			"Error while getting permissions")
	})

	t.Run("retrieve all roles from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := config.EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := NewMongoClient(env, log)
		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		client, _, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		mongoClient.client = client
		mongoClient.roles = rolesCollection
		mongoClient.bindings = bindingsCollection

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveRoles(ctx)
		expected := []types.Role{
			{
				RoleID:            "role1",
				Permissions:       []string{"permission1", "permission2", "foobar"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "role3",
				Permissions:       []string{"permission3", "permission5", "console.project.view"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "notUsedByAnyone",
				Permissions:       []string{"permissionNotUsed1", "permissionNotUsed2"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		assert.Assert(t, reflect.DeepEqual(result, expected),
			"Error while getting permissions")
	})

	t.Run("retrieve all roles by id from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := config.EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
			RolesCollectionName:    "roles",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := NewMongoClient(env, log)
		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		client, _, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		mongoClient.client = client
		mongoClient.roles = rolesCollection
		mongoClient.bindings = bindingsCollection

		ctx := context.Background()

		testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

		result, _ := mongoClient.RetrieveUserRolesByRolesID(ctx, []string{"role1", "role3", "notExistingRole"})
		expected := []types.Role{
			{
				RoleID:            "role1",
				Permissions:       []string{"permission1", "permission2", "foobar"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "role3",
				Permissions:       []string{"permission3", "permission5", "console.project.view"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		assert.Assert(t, reflect.DeepEqual(result, expected),
			"Error while getting permissions")
	})
}

func TestMongoFindOne(t *testing.T) {
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	env := config.EnvironmentVariables{
		MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
		RolesCollectionName:    "roles",
		BindingsCollectionName: "bindings",
	}
	log, _ := test.NewNullLogger()
	mongoClient, err := NewMongoClient(env, log)
	defer mongoClient.Disconnect()
	assert.Assert(t, err == nil, "setup mongo returns error")

	client, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
	mongoClient.client = client
	mongoClient.databaseName = dbName
	mongoClient.roles = rolesCollection
	mongoClient.bindings = bindingsCollection

	ctx := context.Background()

	testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

	t.Run("finds a document", func(t *testing.T) {
		result, err := mongoClient.FindOne(context.Background(), "roles", map[string]interface{}{
			"roleId": "role3",
		})
		assert.NilError(t, err)
		resultMap := result.(map[string]interface{})
		assert.Assert(t, resultMap["_id"] != nil)

		delete(resultMap, "_id")
		assert.DeepEqual(t, result, map[string]interface{}{
			"roleId":    "role3",
			"__STATE__": "PUBLIC",
			"permissions": []interface{}{
				string("permission3"),
				string("permission5"),
				string("console.project.view"),
			},
		})
	})

	t.Run("does not find a document", func(t *testing.T) {
		result, err := mongoClient.FindOne(context.Background(), "roles", map[string]interface{}{
			"key": 42,
		})
		assert.NilError(t, err)
		assert.Assert(t, result == nil)
	})
}

func TestMongoFindMany(t *testing.T) {
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}

	env := config.EnvironmentVariables{
		MongoDBUrl:             fmt.Sprintf("mongodb://%s/test", mongoHost),
		RolesCollectionName:    "roles",
		BindingsCollectionName: "bindings",
	}
	log, _ := test.NewNullLogger()
	mongoClient, err := NewMongoClient(env, log)
	defer mongoClient.Disconnect()
	assert.Assert(t, err == nil, "setup mongo returns error")

	client, dbName, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
	mongoClient.client = client
	mongoClient.databaseName = dbName
	mongoClient.roles = rolesCollection
	mongoClient.bindings = bindingsCollection

	ctx := context.Background()

	testutils.PopulateDBForTesting(t, ctx, rolesCollection, bindingsCollection)

	t.Run("finds multiple documents", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), "roles", map[string]interface{}{
			"$or": []map[string]interface{}{
				{"roleId": "role3"},
				{"roleId": "role9999"},
				{"roleId": "role6"},
			},
		})
		assert.NilError(t, err)

		assert.Equal(t, len(result), 2)
		resultMap := result[0].(map[string]interface{})
		assert.Assert(t, resultMap["_id"] != nil)

		delete(resultMap, "_id")
		assert.DeepEqual(t, resultMap, map[string]interface{}{
			"roleId":    "role3",
			"__STATE__": "PUBLIC",
			"permissions": []interface{}{
				string("permission3"),
				string("permission5"),
				string("console.project.view"),
			},
		})

		result1Map := result[1].(map[string]interface{})
		assert.Assert(t, result1Map["_id"] != nil)

		delete(result1Map, "_id")
		assert.DeepEqual(t, result1Map, map[string]interface{}{
			"roleId":    "role6",
			"__STATE__": "PRIVATE",
			"permissions": []interface{}{
				string("permission3"),
				string("permission5"),
			},
		})
	})

	t.Run("does not find any document", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), "roles", map[string]interface{}{
			"roleId": "role9999",
		})
		assert.NilError(t, err)
		assert.Equal(t, len(result), 0)
	})

	t.Run("returns error on invalid query", func(t *testing.T) {
		result, err := mongoClient.FindMany(context.Background(), "roles", map[string]interface{}{
			"$UNKWNONW": "role9999",
		})
		assert.ErrorContains(t, err, "unknown top level operator")
		assert.Equal(t, len(result), 0)
	})
}

func TestRolesIDSFromBindings(t *testing.T) {
	result := RolesIDsFromBindings([]types.Binding{
		{Roles: []string{"a", "b"}},
		{Roles: []string{"a", "b"}},
		{Roles: []string{"c", "d"}},
		{Roles: []string{"e"}},
	})

	assert.DeepEqual(t, result, []string{"a", "b", "c", "d", "e"})
}

func TestRetrieveUserBindingsAndRoles(t *testing.T) {
	logger, _ := test.NewNullLogger()
	env := config.EnvironmentVariables{
		UserGroupsHeader: "thegroupsheader",
		UserIdHeader:     "theuserheader",
	}

	t.Run("fails if MongoClient is in context but of the wrong type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), types.MongoClientContextKey{}, "test"))

		_, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logger), req, env)
		assert.Error(t, err, "Unexpected error retrieving MongoDB Client from request context")
	})

	t.Run("extract user from request without querying MongoDB", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		user, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logger), req, env)
		assert.NilError(t, err)
		assert.DeepEqual(t, user, types.User{
			UserID:     "userId",
			UserGroups: []string{"group1", "group2"},
		})
	})

	t.Run("extract user with no id in headers does not perform queries", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(WithMongoClient(req.Context(), mock))

		_, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logrus.New()), req, env)
		assert.NilError(t, err)
	})

	t.Run("extract user but retrieve bindings fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(WithMongoClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		_, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logrus.New()), req, env)
		assert.Error(t, err, "Error while retrieving user bindings: some error")
	})

	t.Run("extract user bindings but retrieve roles by role id fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
			},
			UserRolesError: fmt.Errorf("some error 2"),
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(WithMongoClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		_, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logrus.New()), req, env)
		assert.Error(t, err, "Error while retrieving user Roles: some error 2")
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
		req = req.WithContext(WithMongoClient(req.Context(), mock))
		req.Header.Set("thegroupsheader", "group1,group2")
		req.Header.Set("theuserheader", "userId")

		user, err := RetrieveUserBindingsAndRoles(logrus.NewEntry(logrus.New()), req, env)
		assert.NilError(t, err)
		assert.DeepEqual(t, user, types.User{
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
		})
	})
}
