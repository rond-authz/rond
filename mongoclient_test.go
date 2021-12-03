package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"rbac-service/internal/testutils"
	"rbac-service/internal/types"

	"github.com/sirupsen/logrus/hooks/test"
	"go.mongodb.org/mongo-driver/bson"
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
		env := EnvironmentVariables{}
		log, _ := test.NewNullLogger()
		adapter, _ := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "MongoDBUrl is not nil")
	})

	t.Run("if BindingsDatabaseName empty, returns error", func(t *testing.T) {
		env := EnvironmentVariables{
			MongoDBUrl:          "MONGODB_URL",
			MongoDatabaseName:   "something new",
			RolesCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "RolesCollectionName is not nil")
		assert.ErrorContains(t, err, `MongoDB url is not empty, MongoDbName: "something new", BindingsCollectionName: "",  RolesCollectionName: "Some different name"`)
	})

	t.Run("if RolesCollectionName empty, returns error", func(t *testing.T) {
		env := EnvironmentVariables{
			MongoDBUrl:             "MONGODB_URL",
			MongoDatabaseName:      "A name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, adapter == nil, "RolesCollectionName collection is not nil")
		assert.ErrorContains(t, err, `MongoDB url is not empty, MongoDbName: "A name", BindingsCollectionName: "Some different name",  RolesCollectionName: ""`)
	})

	t.Run("throws if mongo url is without protocol", func(t *testing.T) {
		mongoHost := "not-valid-mongo-url"

		env := EnvironmentVariables{
			MongoDBUrl:             mongoHost,
			RolesCollectionName:    "something new",
			MongoDatabaseName:      "A name",
			BindingsCollectionName: "Some different name",
		}
		log, _ := test.NewNullLogger()
		adapter, err := newMongoClient(env, log)
		assert.Assert(t, err != nil, "setup mongo not returns error")
		assert.ErrorContains(t, err, "error connecting to MongoDB")
		assert.Assert(t, adapter == nil)
	})

	t.Run("correctly returns mongodb collection", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s", mongoHost),
			RolesCollectionName:    "roles",
			MongoDatabaseName:      "test",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := newMongoClient(env, log)

		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		assert.Assert(t, mongoClient != nil)
	})
}

func TestMongoCollections(t *testing.T) {
	t.Run("testing retrieve user permissions from mongo", func(t *testing.T) {
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}

		env := EnvironmentVariables{
			MongoDBUrl:             fmt.Sprintf("mongodb://%s", mongoHost),
			RolesCollectionName:    "roles",
			MongoDatabaseName:      "test",
			BindingsCollectionName: "bindings",
		}

		log, _ := test.NewNullLogger()
		mongoClient, err := newMongoClient(env, log)
		defer mongoClient.Disconnect()
		assert.Assert(t, err == nil, "setup mongo returns error")
		client, rolesCollection, bindingsCollection := testutils.GetAndDisposeTestClientsAndCollections(t)
		mongoClient.client = client
		mongoClient.roles = rolesCollection
		mongoClient.bindings = bindingsCollection

		ctx := context.Background()

		roles := []interface{}{
			types.Role{
				RoleID:      "role1",
				Permissions: []string{"permission1", "permission2"},
			},
			types.Role{
				RoleID:      "role3",
				Permissions: []string{"permission3", "permission5"},
			},
		}
		rolesCollection.DeleteMany(ctx, bson.D{})
		rolesCollection.InsertMany(ctx, roles)

		bindings := []interface{}{
			types.Binding{
				BindingID:   "binding1",
				Subjects:    []string{"user1"},
				Roles:       []string{"role1", "role2"},
				Groups:      []string{"group1"},
				Permissions: []string{"permission4"},
			},
			types.Binding{
				BindingID:   "binding2",
				Subjects:    []string{"user1"},
				Roles:       []string{"role3", "role4"},
				Groups:      []string{"group4"},
				Permissions: []string{"permission7"},
			},
			types.Binding{
				BindingID:   "binding3",
				Subjects:    []string{"user5"},
				Roles:       []string{"role3", "role4"},
				Groups:      []string{"group2"},
				Permissions: []string{"permission10", "permission4"},
			},

			types.Binding{
				BindingID:   "binding4",
				Roles:       []string{"role3", "role4"},
				Groups:      []string{"group2"},
				Permissions: []string{"permission11"},
			},

			types.Binding{
				BindingID:   "binding5",
				Subjects:    []string{"user1"},
				Roles:       []string{"role3", "role4"},
				Permissions: []string{"permission12"},
			},
			types.Binding{
				BindingID:   "notUsedByAnyone",
				Subjects:    []string{"user5"},
				Roles:       []string{"role3", "role4"},
				Permissions: []string{"permissionNotUsed"},
			},
		}
		bindingsCollection.DeleteMany(ctx, bson.D{})
		bindingsCollection.InsertMany(ctx, bindings)

		result, _ := mongoClient.FindUserPermissions(ctx, &types.User{UserID: "user1", UserGroups: []string{"group1", "group2"}})
		assert.Assert(t, reflect.DeepEqual(result, []string{
			"permission4",
			"permission7",
			"permission10",
			"permission11",
			"permission12",
			"permission1",
			"permission2",
			"permission3",
			"permission5",
		}),
			"Error while getting permissions")
	})
}
