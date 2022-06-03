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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/v3/assert"
)

func TestProxyOASPath(t *testing.T) {
	t.Run("200 - without oas documentation api defined", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		defer gock.Flush()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/custom/documentation/json" && r.URL.Host == "localhost:3001" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3001").
			Times(2).
			Get("/custom/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/custom/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:3000/custom/documentation/json")

		require.Equal(t, nil, err, "error calling docs")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, gock.IsDone(), "the proxy does not blocks the request for documentations path.")

	})

	t.Run("200 - with oas documentation api defined", func(t *testing.T) {

		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" && r.URL.Host == "localhost:3006" {
				return false
			}
			return true
		})
		gock.New("http://localhost:3006").
			Times(2).
			Get("/documentation/json").
			Reply(200).
			File("./mocks/documentationPathMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3007"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3006"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:3007/documentation/json")

		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, gock.IsDone(), "the proxy allows the request.")
	})

	t.Run("403 - if oas documentation api defined with permission and user has not", func(t *testing.T) {

		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" && r.URL.Host == "localhost:3008" {
				return false
			}
			return true
		})
		gock.New("http://localhost:3008").
			Times(2).
			Get("/documentation/json").
			Reply(200).
			File("./mocks/documentationPathMockWithPermissions.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3009"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3008"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		resp, _ := http.DefaultClient.Get("http://localhost:3009/documentation/json")
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.False(t, gock.IsDone(), "the proxy allows the request.")
	})
}

// FIXME: This function needs to be performed as last in order to make other tests working
func TestEntrypoint(t *testing.T) {
	t.Run("fails for invalid module path, no module found", func(t *testing.T) {
		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_HOST", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/empty-dir"},
		})
		shutdown := make(chan os.Signal, 1)

		entrypoint(shutdown)
		require.True(t, true, "If we get here the service has not started")
		unsetEnvs()
	})

	t.Run("opens server on port 3000", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)
		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			return r.URL.Path != "/documentation/json"
		})
		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()

		time.Sleep(1 * time.Second)
		resp, err := http.DefaultClient.Get("http://localhost:3000/-/rbac-ready")
		require.Equal(t, nil, err)
		require.Equal(t, 200, resp.StatusCode)
	})

	t.Run("GracefulShutdown works properly", func(t *testing.T) {
		defer gock.Off()
		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "DELAY_SHUTDOWN_SECONDS", value: "3"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		shutdown := make(chan os.Signal, 1)
		done := make(chan bool, 1)

		go func() {
			time.Sleep(5 * time.Second)
			done <- false
		}()

		go func() {
			entrypoint(shutdown)
			done <- true
		}()
		shutdown <- syscall.SIGTERM

		flag := <-done
		require.Equal(t, true, flag)
		unsetEnvs()
	})

	t.Run("opa integration", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:3001" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		t.Run("ok - opa evaluation success", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3001/users/").
				Get("/users/").
				Reply(200)
			resp, err := http.DefaultClient.Get("http://localhost:3000/users/")

			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.True(t, gock.IsDone(), "the proxy blocks the request when the permissions are granted.")
		})

		t.Run("forbidden - opa evaluation fail", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3001/").
				Post("/users/").
				Reply(200)
			resp, err := http.DefaultClient.Post("http://localhost:3000/users/", "text/plain", nil)
			require.Equal(t, nil, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "unexpected status code.")
			require.False(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
		})
	})

	t.Run("standalone integration", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "eval/users/" && r.URL.Host == "localhost:3026" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3026"},
			{name: "LOG_LEVEL", value: "trace"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "STANDALONE", value: "true"},
			{name: "BINDINGS_CRUD_SERVICE_URL", value: "http://crud-service"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		t.Run("ok - standalone evaluation success", func(t *testing.T) {
			resp, err := http.DefaultClient.Get("http://localhost:3026/eval/users/")

			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	})

	t.Run("x-permissions is empty", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:3004" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3004").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/mockWithXPermissionEmpty.json")

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3005"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3004"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:3004/").
			Post("/users/").
			Reply(200)
		resp, err := http.DefaultClient.Post("http://localhost:3005/users/", "text/plain", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "unexpected status code.")
		require.False(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with wildcard", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		defer gock.DisableNetworkingFilters()

		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/foo/bar/not/registered/explicitly" && r.URL.Host == "localhost:4000" {
				return false
			}
			return true
		})

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3333"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:4000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/nestedPathsConfig.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:4000/").
			Get("foo/bar/not/registered/explicitly").
			Reply(200)

		resp, err := http.DefaultClient.Get("http://localhost:3333/foo/bar/not/registered/explicitly")
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		defer gock.DisableNetworkingFilters()

		path := "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%252Fcms-backend%252FcmsProperties.json"
		decodedPath, _ := url.PathUnescape(path)

		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == decodedPath && r.URL.Host == "localhost:6000" {
				return false
			}
			return true
		})

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "5555"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		resp, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5555%s", path), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams access", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		defer gock.DisableNetworkingFilters()

		path := "/api/backend/projects/5df2260277baff0011fde823/branches/team-james/files/config-extension%252Fcms-backend%252FcmsProperties.json"
		decodedPath, _ := url.PathUnescape(path)

		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == decodedPath && r.URL.Host == "localhost:6000" {
				return false
			}
			return true
		})

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "5555"},
			{name: "LOG_LEVEL", value: "trace"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		resp, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5555%s", path), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams access with escapde value", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		defer gock.DisableNetworkingFilters()

		path := "/api/backend/projects/5df2260277baff0011fde823/branches/team-%2Fjames/files/config-extension%252Fcms-backend%252FcmsProperties.json"
		decodedPath, _ := url.PathUnescape(path)

		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == decodedPath && r.URL.Host == "localhost:6000" {
				return false
			}
			return true
		})

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "5555"},
			{name: "LOG_LEVEL", value: "trace"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		resp, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5555%s", path), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("mongo integration", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:3002" {
				return false
			}
			if r.URL.Path == "/with-mongo-find-one/some-project" && r.URL.Host == "localhost:3002" {
				return false
			}
			if r.URL.Path == "/with-mongo-find-many/some-project" && r.URL.Host == "localhost:3002" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3002").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMockWithFindBuiltins.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		unsetEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3003"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3002"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies-with-mongo-builtins"},
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
		})

		clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
		client, err := mongo.Connect(context.Background(), clientOpts)
		if err != nil {
			fmt.Printf("error connecting to MongoDB: %s", err.Error())
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFn()
		if err = client.Ping(ctx, readpref.Primary()); err != nil {
			fmt.Printf("error verifying MongoDB connection: %s", err.Error())
		}
		defer client.Disconnect(ctx)

		testutils.PopulateDBForTesting(
			t,
			ctx,
			client.Database(mongoDBName).Collection("roles"),
			client.Database(mongoDBName).Collection("bindings"),
		)

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		t.Run("200 - even without headers", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200)
			resp, err := http.DefaultClient.Get("http://localhost:3003/users/")
			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
		t.Run("200 - integration passed", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200).
				SetHeader("someuserheader", "user1").
				JSON(map[string]string{"foo": "bar"})

			req, err := http.NewRequest("GET", "http://localhost:3003/users/", nil)
			require.NoError(t, err)
			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(ContentTypeHeaderKey, "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)
			require.Equal(t, "user1", resp.Header.Get("someuserheader"))
			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
		t.Run("200 - integration passed without groups", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200).
				SetHeader("headerProxiedTest", "user1")
			req, err := http.NewRequest("GET", "http://localhost:3003/users/", nil)
			require.NoError(t, err)
			client := &http.Client{}
			resp, err := client.Do(req)
			require.Equal(t, "user1", resp.Header.Get("headerProxiedTest"))
			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("200 - integration find_one builtin", func(t *testing.T) {
			doc := struct {
				TenantID  string `bson:"tenantId"`
				ProjectID string `bson:"projectId"`
			}{
				TenantID:  "some-tenant",
				ProjectID: "some-project",
			}

			_, err = client.Database(mongoDBName).Collection("projects").InsertOne(ctx, doc)
			defer client.Database(mongoDBName).Collection("projects").Drop(context.Background())
			require.Equal(t, nil, err)

			gock.Flush()
			gock.New("http://localhost:3002/").
				Get("/with-mongo-find-one").
				Reply(200).
				SetHeader("someuserheader", "user1").
				JSON(map[string]string{"foo": "bar"})

			req, err := http.NewRequest("GET", "http://localhost:3003/with-mongo-find-one/some-project", nil)
			require.NoError(t, err)
			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(ContentTypeHeaderKey, "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)

			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})

		t.Run("200 - integration find_many builtin", func(t *testing.T) {
			type MockData struct {
				TenantID  string `bson:"tenantId"`
				ProjectID string `bson:"projectId"`
			}
			_, err = client.Database(mongoDBName).Collection("projects").InsertOne(ctx, MockData{
				TenantID:  "some-tenant",
				ProjectID: "some-project",
			})
			_, err = client.Database(mongoDBName).Collection("projects").InsertOne(ctx, MockData{
				TenantID:  "some-tenant2",
				ProjectID: "some-project2",
			})

			defer client.Database(mongoDBName).Collection("projects").Drop(context.Background())
			require.Equal(t, nil, err)

			gock.Flush()
			gock.New("http://localhost:3002/").
				Get("/with-mongo-find-many").
				Reply(200).
				SetHeader("someuserheader", "user1").
				JSON(map[string]string{"foo": "bar"})

			req, err := http.NewRequest("GET", "http://localhost:3003/with-mongo-find-many/some-project", nil)
			require.NoError(t, err)

			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(ContentTypeHeaderKey, "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)

			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	})

	t.Run("200 - integration passed with query generation", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:3033" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3033").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMockWithRowFiltering.json")

		unsetBaseEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3034"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3033"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		unsetOtherEnvs := setEnvs([]env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
		})

		clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
		client, err := mongo.Connect(context.Background(), clientOpts)
		if err != nil {
			fmt.Printf("error connecting to MongoDB: %s", err.Error())
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFn()
		if err = client.Ping(ctx, readpref.Primary()); err != nil {
			fmt.Printf("error verifying MongoDB connection: %s", err.Error())
		}
		defer client.Disconnect(ctx)

		testutils.PopulateDBForTesting(
			t,
			ctx,
			client.Database(mongoDBName).Collection("roles"),
			client.Database(mongoDBName).Collection("bindings"),
		)

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetBaseEnvs()
			unsetOtherEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3033/users/").
			Get("/users/").
			MatchHeader("acl_rows", `{"$or":[{"$and":[{"_id":{"$eq":"9876"}}]},{"$and":[{"_id":{"$eq":"12345"}}]},{"$and":[{"_id":{"$eq":"9876"}}]},{"$and":[{"_id":{"$eq":"12345"}}]}]}`).
			Reply(200)
		req, err := http.NewRequest("GET", "http://localhost:3034/users/", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("403 - integration not passed with query generation and without user authenticated", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

		defer gock.Off()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:3035" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3035").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMockWithRowFiltering.json")

		unsetBaseEnvs := setEnvs([]env{
			{name: "HTTP_PORT", value: "3036"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3035"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		unsetOtherEnvs := setEnvs([]env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
		})

		clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
		client, err := mongo.Connect(context.Background(), clientOpts)
		if err != nil {
			fmt.Printf("error connecting to MongoDB: %s", err.Error())
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFn()
		if err = client.Ping(ctx, readpref.Primary()); err != nil {
			fmt.Printf("error verifying MongoDB connection: %s", err.Error())
		}
		defer client.Disconnect(ctx)

		testutils.PopulateDBForTesting(
			t,
			ctx,
			client.Database(mongoDBName).Collection("roles"),
			client.Database(mongoDBName).Collection("bindings"),
		)

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			unsetBaseEnvs()
			unsetOtherEnvs()
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3035/users/").
			Get("/users/").
			Reply(200)
		req, err := http.NewRequest("GET", "http://localhost:3036/users/", nil)
		require.NoError(t, err)

		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestEntrypointWithResponseFiltering(t *testing.T) {
	shutdown := make(chan os.Signal, 1)

	defer gock.Off()
	gock.EnableNetworking()
	gock.NetworkingFilter(func(r *http.Request) bool {
		if r.URL.Path == "/documentation/json" {
			return false
		}
		if r.URL.Path == "/users/" && r.URL.Host == "localhost:3040" {
			return false
		}
		if r.URL.Path == "/filters/" && r.URL.Host == "localhost:3040" {
			return false
		}
		if r.URL.Path == "/body-edit-with-request-filter/" && r.URL.Host == "localhost:3040" {
			return false
		}
		return true
	})

	gock.New("http://localhost:3040").
		Get("/documentation/json").
		Reply(200).
		File("./mocks/mockForResponseFilteringOnResponse.json")

	unsetBaseEnvs := setEnvs([]env{
		{name: "HTTP_PORT", value: "3041"},
		{name: "TARGET_SERVICE_HOST", value: "localhost:3040"},
		{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
		{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
	})
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	unsetOtherEnvs := setEnvs([]env{
		{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
		{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
		{name: "ROLES_COLLECTION_NAME", value: "roles"},
	})

	clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
	client, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		fmt.Printf("error connecting to MongoDB: %s", err.Error())
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		fmt.Printf("error verifying MongoDB connection: %s", err.Error())
	}
	defer client.Disconnect(ctx)

	testutils.PopulateDBForTesting(
		t,
		ctx,
		client.Database(mongoDBName).Collection("roles"),
		client.Database(mongoDBName).Collection("bindings"),
	)

	go func() {
		entrypoint(shutdown)
	}()
	defer func() {
		unsetBaseEnvs()
		unsetOtherEnvs()
		shutdown <- syscall.SIGTERM
	}()
	time.Sleep(1 * time.Second)

	t.Run("200 - without body", func(t *testing.T) {
		gock.Flush()
		gock.New("http://localhost:3040/").
			Get("/users/").
			Reply(200)

		req, err := http.NewRequest("GET", "http://localhost:3041/users/", nil)
		require.NoError(t, err)

		client1 := &http.Client{}
		resp, err := client1.Do(req)
		resp.Body.Close()
		gock.Flush()
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("200 - with correct body filtered returned", func(t *testing.T) {
		gock.Flush()

		gock.New("http://localhost:3040/").
			Get("/filters/").
			Reply(200).
			JSON(map[string]interface{}{"FT_1": true, "TEST_FT_1": true})

		req, _ := http.NewRequest("GET", "http://localhost:3041/filters/", nil)
		client1 := &http.Client{}
		resp, _ := client1.Do(req)
		respBody, _ := ioutil.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, `{"FT_1":true}`, string(respBody))
	})

	t.Run("200 - with request filter policy", func(t *testing.T) {
		gock.Flush()

		gock.New("http://localhost:3040/").
			Get("/body-edit-with-request-filter/").
			MatchHeader("acl_rows", `{"$or":[{"$and":[{"key":{"$eq":42}}]}]}`).
			Reply(200).
			JSON(map[string]interface{}{"FT_1": true, "TEST_FT_1": true})

		req, _ := http.NewRequest("GET", "http://localhost:3041/body-edit-with-request-filter/", nil)
		client1 := &http.Client{}
		resp, _ := client1.Do(req)
		respBody, _ := ioutil.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, `{"FT_1":true}`, string(respBody))
	})
}

type env struct {
	name  string
	value string
}

func setEnvs(envsToSet []env) func() {
	for _, env := range envsToSet {
		os.Setenv(env.name, env.value)
	}

	return func() {
		for _, env := range envsToSet {
			os.Unsetenv(env.name)
		}
	}
}

func TestIntegrationWithOASParamsInBrackets(t *testing.T) {
	shutdown := make(chan os.Signal, 1)

	defer gock.Off()
	gock.EnableNetworking()
	gock.NetworkingFilter(func(r *http.Request) bool {
		if r.URL.Path == "/documentation/json" {
			return false
		}
		if r.URL.Path == "/api/backend/projects/testabc/" && r.URL.Host == "localhost:3050" {
			return false
		}
		return true
	})

	gock.New("http://localhost:3050").
		Get("/documentation/json").
		Reply(200).
		File("./mocks/routesWithSamePath.json")

	unsetBaseEnvs := setEnvs([]env{
		{name: "HTTP_PORT", value: "3051"},
		{name: "TARGET_SERVICE_HOST", value: "localhost:3050"},
		{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
		{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
	})
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	unsetOtherEnvs := setEnvs([]env{
		{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
		{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
		{name: "ROLES_COLLECTION_NAME", value: "roles"},
	})

	clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
	client, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		fmt.Printf("error connecting to MongoDB: %s", err.Error())
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		fmt.Printf("error verifying MongoDB connection: %s", err.Error())
	}

	defer client.Disconnect(ctx)

	testutils.PopulateDBForTesting(
		t,
		ctx,
		client.Database(mongoDBName).Collection("roles"),
		client.Database(mongoDBName).Collection("bindings"),
	)

	go func() {
		entrypoint(shutdown)
	}()
	defer func() {
		unsetBaseEnvs()
		unsetOtherEnvs()
		shutdown <- syscall.SIGTERM
	}()
	time.Sleep(1 * time.Second)

	t.Run("200 - without body", func(t *testing.T) {
		gock.Flush()
		gock.New("http://localhost:3050/").
			Get("/api/backend/projects/testabc/").
			Reply(200)

		req, err := http.NewRequest("GET", "http://localhost:3051/api/backend/projects/testabc/", nil)
		require.NoError(t, err)

		client1 := &http.Client{}
		resp, err := client1.Do(req)
		resp.Body.Close()
		gock.Flush()
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestSetupRouterStandaloneMode(t *testing.T) {
	defer gock.Off()
	defer gock.Flush()

	log, _ := test.NewNullLogger()
	env := config.EnvironmentVariables{
		Standalone:           true,
		TargetServiceHost:    "my-service:4444",
		PathPrefixStandalone: "/my-prefix",
	}
	opa := &OPAModuleConfig{
		Name: "policies",
		Content: `package policies
test_policy { true }
`,
	}
	oas := &OpenAPISpec{
		Paths: OpenAPIPaths{
			"/evalapi": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "test_policy",
					},
				},
			},
		},
	}

	var mongoClient *mongoclient.MongoClient
	evaluatorsMap, err := setupEvaluators(context.TODO(), mongoClient, oas, opa, env)
	assert.NilError(t, err, "unexpected error")

	router, err := setupRouter(log, env, opa, oas, evaluatorsMap, mongoClient)
	assert.NilError(t, err, "unexpected error")

	t.Run("some eval API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/my-prefix/evalapi", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("revoke API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/revoke/bindings/resource/some-resource", nil)
		router.ServeHTTP(w, req)

		// Bad request expected for missing body and so decoder fails!
		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

		var requestError types.RequestError
		err := json.Unmarshal(w.Body.Bytes(), &requestError)
		assert.NilError(t, err, "unexpected error")
		assert.Equal(t, requestError.Message, "Internal server error, please try again later")
		assert.Equal(t, requestError.Error, "EOF")
	})

	t.Run("grant API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/grant/bindings/resource/some-resource", nil)
		router.ServeHTTP(w, req)

		// Bad request expected for missing body and so decoder fails!
		assert.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

		var requestError types.RequestError
		err := json.Unmarshal(w.Body.Bytes(), &requestError)
		assert.NilError(t, err, "unexpected error")
		assert.Equal(t, requestError.Message, "Internal server error, please try again later")
		assert.Equal(t, requestError.Error, "EOF")
	})
}
