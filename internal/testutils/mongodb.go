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

package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rond-authz/rond/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const LocalhostMongoDB = "localhost:27017"
const nameDictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func GetRandomName(n int) string {
	samples := lo.Samples(strings.Split(nameDictionary, ""), n)
	return strings.Join(samples, "")
}

func GetMongoHost(t testing.TB) string {
	t.Helper()

	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	return mongoHost
}

// GetAndDisposeTestCollection returns a collection from a random database.
// The function performs test clean up by dropping the database and closing MongoDB client connection.
func GetAndDisposeTestClientsAndCollections(t *testing.T) (*mongo.Client, string, *mongo.Collection, *mongo.Collection) {
	t.Helper()

	client := GetMongoClient(t)
	db, rolesCollection, bindingsCollection := GetDBAndCollections(t, client)

	//#nosec G104 -- Ignored errors
	t.Cleanup(func() {
		// This sleep has been added to avoid mongo race condition
		time.Sleep(100 * time.Millisecond)
		if err := db.Drop(context.Background()); err != nil {
			t.Fatalf("drop collcetion failed %s", err.Error())
		}
		if err := client.Disconnect(context.Background()); err != nil {
			t.Fatalf("db disconnect failed %s", err.Error())
		}
	})

	return client, db.Name(), rolesCollection, bindingsCollection
}

// GetMongoClient returns a mongodb client. The function does not perform any cleanup, you have to
// manually disconnect from the client.
func GetMongoClient(t *testing.T) *mongo.Client {
	t.Helper()
	// Getting MongoHost in CI from standard environment variable.
	mongoHost := GetMongoHost(t)
	clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
	client, err := mongo.Connect(context.Background(), clientOpts)
	require.NoError(t, err, "failed mongo db connection")

	return client
}

// GetDBAndCollections returns a random database and collection.
// The function does not perform any cleanup, you have to
// manually disconnect from the client.
func GetDBAndCollections(t *testing.T, client *mongo.Client) (*mongo.Database, *mongo.Collection, *mongo.Collection) {
	dbName := GetRandomName(10)
	db := client.Database(dbName)
	return db, db.Collection("roles"), db.Collection("bindings")
}

func AssertResponseError(t *testing.T, resp *httptest.ResponseRecorder, statusCode int, technicalErrMsg string) {
	AssertResponseFullErrorMessages(t, resp, statusCode, technicalErrMsg, "")
}

func AssertResponseFullErrorMessages(t *testing.T, resp *httptest.ResponseRecorder, statusCode int, technicalErrMsg, businessErrMsg string) {
	t.Helper()
	respBodyBuff, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Unexpected error in the response body")

	var respBody types.RequestError
	err = json.Unmarshal(respBodyBuff, &respBody)
	require.NoError(t, err, "Unexpected error during unmarshalling of the response body")

	require.Equal(t, statusCode, respBody.StatusCode, "Unexpected status code")

	if technicalErrMsg != "" {
		require.Equal(t, technicalErrMsg, respBody.Error, "Unexpected technical error message")
	}

	if businessErrMsg != "" {
		require.Equal(t, businessErrMsg, respBody.Message, "Unexpected technical error message")
	}
}

// #nosec G104 -- Ignored errors
func PopulateDBForTesting(
	t *testing.T,
	ctx context.Context,
	rolesCollection *mongo.Collection,
	bindingsCollection *mongo.Collection,
) {
	t.Helper()
	roles := []interface{}{
		types.Role{
			RoleID:            "role1",
			RoleName:          "Role1",
			Permissions:       []string{"permission1", "permission2", "foobar"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Role{
			RoleID:            "role3",
			RoleName:          "Role3",
			Permissions:       []string{"permission3", "permission5", "console.project.view"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Role{
			RoleID:            "role6",
			RoleName:          "Role6",
			Permissions:       []string{"permission3", "permission5"},
			CRUDDocumentState: "PRIVATE",
		},
		types.Role{
			RoleID:            "notUsedByAnyone",
			RoleName:          "Not Used By Anyone",
			Permissions:       []string{"permissionNotUsed1", "permissionNotUsed2"},
			CRUDDocumentState: "PUBLIC",
		},
	}
	if _, err := rolesCollection.DeleteMany(ctx, bson.D{}); err != nil {
		t.Fatalf("roles collection delete failed: %s", err.Error())
	}
	if _, err := rolesCollection.InsertMany(ctx, roles); err != nil {
		t.Fatalf("roles collection insert failed: %s", err.Error())
	}

	bindings := []interface{}{
		types.Binding{
			BindingID:         "binding1",
			Subjects:          []string{"user1"},
			Roles:             []string{"role1", "role2"},
			Groups:            []string{"group1"},
			Permissions:       []string{"permission4"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Binding{
			BindingID:         "binding2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group4"},
			Permissions:       []string{"permission7"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Binding{
			BindingID:         "binding3",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission10", "permission4"},
			CRUDDocumentState: "PUBLIC",
		},

		types.Binding{
			BindingID:         "binding4",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission11"},
			CRUDDocumentState: "PUBLIC",
		},

		types.Binding{
			BindingID:         "bindingForRowFiltering",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "9876"},
			CRUDDocumentState: "PUBLIC",
		},

		types.Binding{
			BindingID:         "bindingForRowFilteringFromSubject",
			Subjects:          []string{"filter_test"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "12345"},
			CRUDDocumentState: "PUBLIC",
		},

		types.Binding{
			BindingID:         "binding5",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permission12"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Binding{
			BindingID:         "notUsedByAnyone",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PUBLIC",
		},
		types.Binding{
			BindingID:         "notUsedByAnyone2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role6"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PRIVATE",
		},
	}
	if _, err := bindingsCollection.DeleteMany(ctx, bson.D{}); err != nil {
		t.Fatalf("bindings collection delete failed: %s", err.Error())
	}
	if _, err := bindingsCollection.InsertMany(ctx, bindings); err != nil {
		t.Fatalf("bindings collection insert failed: %s", err.Error())
	}
}
