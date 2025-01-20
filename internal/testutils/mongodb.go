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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rond-authz/rond/types"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/rand"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const LocalhostMongoDB = "localhost:27017"
const nameDictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func init() {
	if !testing.Testing() {
		panic("You are using internal/testutils package in production code. Don't do that!")
	}

	// #nosec G115 -- Coverting a signed to unsigned integer may cause an integer overflow
	// when dealing with negative numbers. This is not the case here, since the source is
	// time.Now().UnixNano() which is always positive.
	// Moreover, this is a test utility file so it won't affect production code.
	//
	//  - CWE-190 https://cwe.mitre.org/data/definitions/190.html
	source := uint64(time.Now().UnixNano())
	rand.New(rand.NewSource(source))
}

func formatMongoDBURL(mongoHost, dbName string) string {
	return fmt.Sprintf("mongodb://%s/%s", mongoHost, dbName)
}

func GetMongoDBURL(t *testing.T) string {
	return formatMongoDBURL(
		GetMongoHost(t),
		GetRandomName(10),
	)
}

func GetAndDisposeMongoClient(t *testing.T) (*mongo.Client, string) {
	t.Helper()

	mongoHost := GetMongoHost(t)
	dbName := GetRandomName(10)

	clientOpts := options.Client().ApplyURI(formatMongoDBURL(mongoHost, dbName))

	client, err := mongo.Connect(context.Background(), clientOpts)
	require.NoError(t, err, "failed mongo db connection")

	t.Cleanup(disposeFactory(t, client, dbName))
	return client, dbName
}

// GetAndDisposeTestCollection returns a collection from a random database.
// The function performs test clean up by dropping the database and closing MongoDB client connection.
// The returned collections are meant to be used for roles and bindings, respectively.
func GetAndDisposeTestClientsAndCollections(t *testing.T) (*mongo.Client, string, *mongo.Collection, *mongo.Collection) {
	t.Helper()

	client, dbName := GetAndDisposeMongoClient(t)

	rolesCollection := client.Database(dbName).Collection("roles")
	bindingsCollection := client.Database(dbName).Collection("bindings")

	return client, dbName, rolesCollection, bindingsCollection
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

func disposeFactory(t *testing.T, client *mongo.Client, dbName string) func() {
	t.Helper()
	dispose := func() {
		// This sleep has been added to avoid mongo race condition
		time.Sleep(100 * time.Millisecond)
		if err := client.Database(dbName).Drop(context.Background()); err != nil {
			t.Fatalf("drop collcetion failed %s", err.Error())
		}
		if err := client.Disconnect(context.Background()); err != nil {
			t.Fatalf("db disconnect failed %s", err.Error())
		}
	}
	return dispose
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
