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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/internal/utils"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/metrics"
	rondprometheus "github.com/rond-authz/rond/metrics/prometheus"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"
	"github.com/rond-authz/rond/service"
	"github.com/rond-authz/rond/types"

	"github.com/caarlos0/env/v11"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"gopkg.in/h2non/gock.v1"
)

func getEnvs(t *testing.T, envMap map[string]string) config.EnvironmentVariables {
	envs, err := env.ParseAsWithOptions[config.EnvironmentVariables](env.Options{
		Environment: envMap,
	})
	require.NoError(t, err)

	return envs
}

func TestProxyOASPath(t *testing.T) {
	log, _ := test.NewNullLogger()
	t.Run("200 - without oas documentation api defined", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"TARGET_SERVICE_HOST":     "localhost:3001",
			"TARGET_SERVICE_OAS_PATH": "/custom/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)

		require.True(t, <-app.sdkBootState.IsReadyChan())

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/custom/documentation/json", nil)
		app.router.ServeHTTP(w, req)

		require.NoError(t, err, "error calling docs")
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		require.True(t, gock.IsDone(), "the proxy does not blocks the request for documentations path.")
	})

	t.Run("200 - with oas documentation api defined", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"TARGET_SERVICE_HOST":     "localhost:3006",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)

		require.True(t, <-app.sdkBootState.IsReadyChan())

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/documentation/json", nil)
		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		require.True(t, gock.IsDone(), "the proxy allows the request.")
	})

	t.Run("403 - if oas documentation api defined with permission and user has not", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":               "3009",
			"TARGET_SERVICE_HOST":     "localhost:3008",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/documentation/json", nil)
		app.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusForbidden, w.Result().StatusCode)
		require.False(t, gock.IsDone(), "the proxy allows the request.")
	})
}

func TestSetupApp(t *testing.T) {
	log, _ := test.NewNullLogger()

	t.Run("fails for invalid module path, no module found", func(t *testing.T) {
		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":               "3000",
			"TARGET_SERVICE_HOST":     "localhost:3001",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/empty-dir",
			"LOG_LEVEL":               "fatal",
		})

		_, err := setupService(envs, log)
		require.EqualError(t, err, core.ErrMissingRegoModules.Error())
	})

	t.Run("opa integration", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if (r.URL.Path == "/users/" || r.URL.Path == "/assert-user") && r.URL.Host == "localhost:3001" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		envs := getEnvs(t, map[string]string{
			"TARGET_SERVICE_HOST":     "localhost:3001",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		t.Run("ok - opa evaluation success", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3001/users/").
				Get("/users/").
				Reply(200)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			app.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
			require.True(t, gock.IsDone(), "the proxy blocks the request when the permissions are granted.")
		})

		t.Run("ok - user assertions", func(t *testing.T) {
			gock.Flush()

			gock.New("http://localhost:3001/").
				Get("/assert-user").
				Reply(200)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/assert-user", nil)
			req.Header.Set("miauserid", "the-user-id")
			app.router.ServeHTTP(w, req)

			app.router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Result().StatusCode)

			require.True(t, gock.IsDone(), "the proxy blocks the request when the permissions are granted.")
		})

		t.Run("forbidden - opa evaluation fail", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3001/").
				Post("/users/").
				Reply(200)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/users/", nil)
			app.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "unexpected status code.")
			require.False(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
		})
	})

	t.Run("standalone integration", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "3026",
			"LOG_LEVEL":                 "fatal",
			"TARGET_SERVICE_HOST":       "localhost:3001",
			"TARGET_SERVICE_OAS_PATH":   "/documentation/json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"STANDALONE":                "true",
			"BINDINGS_CRUD_SERVICE_URL": "http://crud-service",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		t.Run("ok - standalone evaluation success", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/eval/users/", nil)
			app.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})

	t.Run("x-permissions is empty", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":               "3005",
			"TARGET_SERVICE_HOST":     "localhost:3004",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:3004/").
			Post("/users/").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/users/", nil)
		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "unexpected status code.")
		require.False(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with wildcard", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()

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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "3333",
			"TARGET_SERVICE_HOST":       "localhost:4000",
			"API_PERMISSIONS_FILE_PATH": "./mocks/nestedPathsConfig.json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"LOG_LEVEL":                 "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:4000/").
			Get("foo/bar/not/registered/explicitly").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/foo/bar/not/registered/explicitly", nil)
		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()

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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "5555",
			"TARGET_SERVICE_HOST":       "localhost:6000",
			"API_PERMISSIONS_FILE_PATH": "./mocks/mockForEncodedTest.json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"LOG_LEVEL":                 "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams access", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()

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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "5556",
			"TARGET_SERVICE_HOST":       "localhost:6000",
			"API_PERMISSIONS_FILE_PATH": "./mocks/mockForEncodedTest.json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"LOG_LEVEL":                 "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		app.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams access with escaped value", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()

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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "5557",
			"TARGET_SERVICE_HOST":       "localhost:6000",
			"API_PERMISSIONS_FILE_PATH": "./mocks/mockForEncodedTest.json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"LOG_LEVEL":                 "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		app.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path registered with and without trailing slash when ignoreTrailingSlash is true", func(t *testing.T) {
		gock.Flush()

		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()

		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/with/trailing/slash/" && r.URL.Host == "localhost:3339" {
				return false
			}
			if r.URL.Path == "/with/trailing/slash" && r.URL.Host == "localhost:3339" {
				return false
			}
			if r.URL.Path == "/without/trailing/slash" && r.URL.Host == "localhost:3339" {
				return false
			}
			if r.URL.Path == "/without/trailing/slash/" && r.URL.Host == "localhost:3339" {
				return false
			}
			if r.URL.Path == "/ignore/trailing/slash" && r.URL.Host == "localhost:3339" {
				return false
			}
			if r.URL.Path == "/ignore/trailing/slash/" && r.URL.Host == "localhost:3339" {
				return false
			}

			return true
		})

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                 "5559",
			"TARGET_SERVICE_HOST":       "localhost:3339",
			"API_PERMISSIONS_FILE_PATH": "./mocks/nestedPathsConfig.json",
			"OPA_MODULES_DIRECTORY":     "./mocks/rego-policies",
			"LOG_LEVEL":                 "fatal",
		})

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.New("http://localhost:3339").
			Get("/with/trailing/slash/").
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})

		gock.New("http://localhost:3339").
			Get("/with/trailing/slash").
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})

		gock.New("http://localhost:3339").
			Post("/without/trailing/slash").
			Reply(200)

		gock.New("http://localhost:3339").
			Post("/without/trailing/slash/").
			Reply(200)

		gock.New("http://localhost:3339").
			Get("/ignore/trailing/slash/").
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})

		gock.New("http://localhost:3339").
			Get("/ignore/trailing/slash").
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})

		resp1 := httptest.NewRecorder()
		req1 := httptest.NewRequest(http.MethodGet, "/with/trailing/slash/", nil)
		app.router.ServeHTTP(resp1, req1)
		require.Equal(t, http.StatusOK, resp1.Result().StatusCode, "unexpected status code.")

		respBody1, _ := io.ReadAll(resp1.Body)
		require.Equal(t, "\"/with/trailing/slash/\"", string(respBody1))

		resp2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/with/trailing/slash", nil)
		app.router.ServeHTTP(resp2, req2)
		require.Equal(t, http.StatusOK, resp2.Result().StatusCode, "unexpected status code.")

		respBody2, _ := io.ReadAll(resp2.Body)
		require.Equal(t, "\"/with/trailing/slash\"", string(respBody2))

		resp3 := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/without/trailing/slash", nil)
		app.router.ServeHTTP(resp3, req)
		require.Equal(t, http.StatusOK, resp3.Result().StatusCode, "unexpected status code.")

		resp4 := httptest.NewRecorder()
		req4 := httptest.NewRequest(http.MethodPost, "/without/trailing/slash/", nil)
		app.router.ServeHTTP(resp4, req4)
		require.Equal(t, http.StatusOK, resp4.Result().StatusCode, "unexpected status code.")

		resp5 := httptest.NewRecorder()
		req5 := httptest.NewRequest(http.MethodGet, "/ignore/trailing/slash/", nil)
		app.router.ServeHTTP(resp5, req5)
		require.Equal(t, http.StatusOK, resp5.Result().StatusCode, "unexpected status code.")

		respBody5, _ := io.ReadAll(resp5.Body)
		require.Equal(t, "\"/ignore/trailing/slash/\"", string(respBody5))

		resp6 := httptest.NewRecorder()
		req6 := httptest.NewRequest(http.MethodGet, "/ignore/trailing/slash", nil)
		app.router.ServeHTTP(resp6, req6)
		require.Equal(t, http.StatusOK, resp6.Result().StatusCode, "unexpected status code.")

		respBody6, _ := io.ReadAll(resp6.Body)
		require.Equal(t, "\"/ignore/trailing/slash\"", string(respBody6))

		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("mongo integration", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3003",
			"TARGET_SERVICE_HOST":      "localhost:3002",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies-with-mongo-builtins",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
			"LOG_LEVEL":                "fatal",
		})

		clientOpts := options.Client().ApplyURI(fmt.Sprintf("mongodb://%s", mongoHost))
		client, err := mongo.Connect(context.Background(), clientOpts)
		if err != nil {
			t.Errorf("error connecting to MongoDB: %s", err.Error())
		}

		ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFn()
		if err = client.Ping(ctx, readpref.Primary()); err != nil {
			t.Errorf("error verifying MongoDB connection: %s", err.Error())
		}
		defer client.Disconnect(ctx)

		testutils.PopulateDBForTesting(
			t,
			ctx,
			client.Database(mongoDBName).Collection("roles"),
			client.Database(mongoDBName).Collection("bindings"),
		)

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		t.Run("200 - even without headers", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			app.router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("200 - integration passed", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200).
				SetHeader("someuserheader", "user1").
				JSON(map[string]string{"foo": "bar"})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/users/", nil)
			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")

			app.router.ServeHTTP(w, req)
			require.Equal(t, "user1", w.Result().Header.Get("someuserheader"))
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("200 - integration passed without groups", func(t *testing.T) {
			gock.Flush()
			gock.New("http://localhost:3002/users/").
				Get("/users/").
				Reply(200).
				SetHeader("headerProxiedTest", "user1")
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3003/users/", nil)
			app.router.ServeHTTP(w, req)

			require.Equal(t, "user1", w.Result().Header.Get("headerProxiedTest"))
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
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

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost:3003/with-mongo-find-one/some-project", nil)
			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")

			app.router.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Result().StatusCode)
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

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/with-mongo-find-many/some-project", nil)
			req.Header.Set("miauserid", "user1")
			req.Header.Set("miausergroups", "user1,user2")
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")

			app.router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})

	t.Run("200 - integration passed with query generation", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3034",
			"TARGET_SERVICE_HOST":      "localhost:3033",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3033/users/").
			Get("/users/").
			MatchHeader("acl_rows", `{"$or":[{"$and":[{"_id":{"$eq":"9876"}}]},{"$and":[{"_id":{"$eq":"12345"}}]},{"$and":[{"_id":{"$eq":"9876"}}]},{"$and":[{"_id":{"$eq":"12345"}}]}]}`).
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("200 - integration passed with x-rond configuration in oas", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/users/" && r.URL.Host == "localhost:5033" {
				return false
			}
			return true
		})

		gock.New("http://localhost:5033").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/rondOasConfig.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "5034",
			"TARGET_SERVICE_HOST":      "localhost:5033",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:5033/users/").
			Get("/users/").
			MatchHeader("x-query-header", `{"$or":[{"$and":[{"name":{"$eq":"jane"}}]}]}`).
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		bodyBytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		require.Equal(t, `{"msg":"hey there"}`, string(bodyBytes))
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("403 - integration not passed with query generation and without user authenticated", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
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

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3036",
			"TARGET_SERVICE_HOST":      "localhost:3035",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3035/users/").
			Get("/users/").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3036/users/", nil)

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("200 - test correcting routing", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/foo/count" && r.URL.Host == "localhost:3038" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3038").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/pathsWithWildCardCollision.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3039",
			"TARGET_SERVICE_HOST":      "localhost:3038",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Get("/foo/count").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3039/foo/count", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("200 - test correcting routing inverted oas", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/foo/count" && r.URL.Host == "localhost:3038" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3038").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/pathsWithWildCardCollision2.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3060",
			"TARGET_SERVICE_HOST":      "localhost:3038",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Get("/foo/count").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3060/foo/count", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("200 - test correcting routing with pathParameters", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/foo/count" && r.URL.Host == "localhost:3038" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3038").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/pathsWithWildCardCollision.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3070",
			"TARGET_SERVICE_HOST":      "localhost:3038",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Patch("/foo/count").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest("PATCH", "http://localhost:3070/foo/count", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("200 - test correcting routing with pathParameters on compex OAS", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			if r.URL.Path == "/documentation/json" {
				return false
			}
			if r.URL.Path == "/api/restaurants/1234" && r.URL.Host == "localhost:3043" {
				return false
			}
			return true
		})

		gock.New("http://localhost:3043").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/oasExampleCrud.json")

		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":                "3044",
			"TARGET_SERVICE_HOST":      "localhost:3043",
			"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
			"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
			"LOG_LEVEL":                "fatal",
			"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
			"BINDINGS_COLLECTION_NAME": "bindings",
			"ROLES_COLLECTION_NAME":    "roles",
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

		app, err := setupService(envs, log)
		require.NoError(t, err)
		require.True(t, <-app.sdkBootState.IsReadyChan())

		gock.Flush()
		gock.New("http://localhost:3043").
			Get("/api/restaurants/1234").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3044/api/restaurants/1234", nil)
		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")

		app.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestEntrypointWithResponseFiltering(t *testing.T) {
	log, _ := test.NewNullLogger()

	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.DisableNetworking()
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

	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	envs := getEnvs(t, map[string]string{
		"HTTP_PORT":                "3041",
		"TARGET_SERVICE_HOST":      "localhost:3040",
		"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
		"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
		"LOG_LEVEL":                "fatal",
		"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
		"BINDINGS_COLLECTION_NAME": "bindings",
		"ROLES_COLLECTION_NAME":    "roles",
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

	app, err := setupService(envs, log)
	require.NoError(t, err)
	require.True(t, <-app.sdkBootState.IsReadyChan())

	t.Run("200 - without body", func(t *testing.T) {
		gock.Flush()
		gock.New("http://localhost:3040/").
			Get("/users/").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3041/users/", nil)

		app.router.ServeHTTP(w, req)

		w.Result().Body.Close()
		gock.Flush()
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("200 - with correct body filtered returned", func(t *testing.T) {
		gock.Flush()

		gock.New("http://localhost:3040/").
			Get("/filters/").
			Reply(200).
			JSON(map[string]interface{}{"FT_1": true, "TEST_FT_1": true})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3041/filters/", nil)

		app.router.ServeHTTP(w, req)

		respBody, _ := io.ReadAll(w.Result().Body)
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		require.Equal(t, `{"FT_1":true}`, string(respBody))
	})

	t.Run("200 - with request filter policy", func(t *testing.T) {
		gock.Flush()

		gock.New("http://localhost:3040/").
			Get("/body-edit-with-request-filter/").
			MatchHeader("acl_rows", `{"$or":[{"$and":[{"key":{"$eq":42}}]}]}`).
			Reply(200).
			JSON(map[string]interface{}{"FT_1": true, "TEST_FT_1": true})

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3041/body-edit-with-request-filter/", nil)

		app.router.ServeHTTP(w, req)

		respBody, _ := io.ReadAll(w.Result().Body)
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		require.Equal(t, `{"FT_1":true}`, string(respBody))
	})
}

func TestIntegrationWithOASParamsInBrackets(t *testing.T) {
	log, _ := test.NewNullLogger()

	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.DisableNetworking()
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

	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	envs := getEnvs(t, map[string]string{
		"HTTP_PORT":                "3051",
		"TARGET_SERVICE_HOST":      "localhost:3050",
		"TARGET_SERVICE_OAS_PATH":  "/documentation/json",
		"OPA_MODULES_DIRECTORY":    "./mocks/rego-policies",
		"LOG_LEVEL":                "fatal",
		"MONGODB_URL":              fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName),
		"BINDINGS_COLLECTION_NAME": "bindings",
		"ROLES_COLLECTION_NAME":    "roles",
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

	app, err := setupService(envs, log)
	require.NoError(t, err)
	require.True(t, <-app.sdkBootState.IsReadyChan())

	t.Run("200 - without body", func(t *testing.T) {
		gock.Flush()
		gock.New("http://localhost:3050/").
			Get("/api/backend/projects/testabc/").
			Reply(200)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://localhost:3051/api/backend/projects/testabc/", nil)

		app.router.ServeHTTP(w, req)

		w.Result().Body.Close()
		gock.Flush()
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestSetupRouterStandaloneMode(t *testing.T) {
	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.Flush()

	log, _ := test.NewNullLogger()

	env := config.EnvironmentVariables{
		Standalone:               true,
		TargetServiceHost:        "my-service:4444",
		PathPrefixStandalone:     "/my-prefix",
		ServiceVersion:           "my-version",
		BindingsCrudServiceURL:   "http://crud:3030",
		AdditionalHeadersToProxy: "miauserid",
	}
	opa := core.MustNewOPAModuleConfig([]core.Module{
		{
			Name: "policies",
			Content: `package policies
test_policy { true }

filter_policy {
	query := data.resources[_]
	query.answer = 42
}
`,
		},
	})
	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/evalapi": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{PolicyName: "test_policy"},
					},
				},
			},
			"/evalfilter": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{
							PolicyName:    "filter_policy",
							GenerateQuery: true,
							QueryOptions:  core.QueryOptions{HeaderName: "my-query"},
						},
					},
				},
			},
		},
	}

	logger, _ := test.NewNullLogger()
	rondSDK, err := sdk.NewFromOAS(context.Background(), opa, oas, &sdk.Options{
		EvaluatorOptions: &sdk.EvaluatorOptions{},
		Logger:           rondlogrus.NewLogger(logger),
	})
	require.NoError(t, err, "unexpected error")

	sdkState := service.NewSDKBootState()
	sdkState.Ready(rondSDK)
	router, err := service.SetupRouter(log, env, opa, oas, sdkState, nil, nil)
	require.NoError(t, err, "unexpected error")

	t.Run("some eval API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/my-prefix/evalapi", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("eval with request filter generation", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/my-prefix/evalfilter", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		queryHeader := w.Header().Get("my-query")
		require.Equal(t, `{"$or":[{"$and":[{"answer":{"$eq":42}}]}]}`, queryHeader)
	})

	t.Run("revoke API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/revoke/bindings/resource/some-resource", nil)
		router.ServeHTTP(w, req)

		// Bad request expected for missing body and so decoder fails!
		require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

		var requestError types.RequestError
		err := json.Unmarshal(w.Body.Bytes(), &requestError)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, "Internal server error, please try again later", requestError.Message)
		require.Equal(t, "EOF", requestError.Error)
	})

	t.Run("grant API", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/grant/bindings/resource/some-resource", nil)
		router.ServeHTTP(w, req)

		// Bad request expected for missing body and so decoder fails!
		require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

		var requestError types.RequestError
		err := json.Unmarshal(w.Body.Bytes(), &requestError)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, "Internal server error, please try again later", requestError.Message)
		require.Equal(t, "EOF", requestError.Error)
	})

	t.Run("grant API with headers to proxy", func(t *testing.T) {
		reqBody := service.GrantRequestBody{
			ResourceID:  "my-company",
			Subjects:    []string{"subj"},
			Groups:      []string{"group1"},
			Roles:       []string{"role1"},
			Permissions: []string{"permission1"},
		}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.Nil(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		gock.New("http://crud:3030").
			Post("/").
			MatchHeader("miauserid", "my user id to proxy").
			Reply(200).
			JSON([]byte(`{"_id":"theobjectid"}`))

		req := httptest.NewRequest(http.MethodPost, "/grant/bindings/resource/some-resource", bytes.NewReader(reqBodyBytes))
		req.Header.Set("miauserid", "my user id to proxy")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("API documentation is correctly exposed - json", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/openapi/json", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)

		responseBody := getResponseBody(t, w)
		require.True(t, string(responseBody) != "")
	})

	t.Run("API documentation is correctly exposed - yaml", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/openapi/yaml", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)

		responseBody := getResponseBody(t, w)
		require.True(t, string(responseBody) != "")
	})
}

func TestSetupRouterMetrics(t *testing.T) {
	defer gock.Off()
	defer gock.DisableNetworkingFilters()
	defer gock.Flush()

	log, _ := test.NewNullLogger()

	env := config.EnvironmentVariables{
		Standalone:               true,
		TargetServiceHost:        "my-service:4444",
		PathPrefixStandalone:     "/my-prefix",
		ServiceVersion:           "my-version",
		BindingsCrudServiceURL:   "http://crud:3030",
		AdditionalHeadersToProxy: "miauserid",
		ExposeMetrics:            true,
	}
	opa := core.MustNewOPAModuleConfig([]core.Module{
		{
			Name: "policies",
			Content: `package policies
test_policy { true }

filter_policy {
	query := data.resources[_]
	query.answer = 42
}
`,
		},
	})
	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/evalapi": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{PolicyName: "test_policy"},
					},
				},
			},
			"/evalfilter": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &core.RondConfig{
						RequestFlow: core.RequestFlow{
							PolicyName:    "filter_policy",
							GenerateQuery: true,
							QueryOptions:  core.QueryOptions{HeaderName: "my-query"},
						},
					},
				},
			},
		},
	}

	registry := prometheus.NewRegistry()
	logger, _ := test.NewNullLogger()
	m := rondprometheus.SetupMetrics(registry)
	rondSDK, err := sdk.NewFromOAS(context.Background(), opa, oas, &sdk.Options{
		Logger:  rondlogrus.NewLogger(logger),
		Metrics: m,
	})
	require.NoError(t, err, "unexpected error")

	m.PolicyEvaluationDurationMilliseconds.With(metrics.Labels{
		"policy_name": "myPolicy",
	}).Observe(123)
	sdkState := service.NewSDKBootState()
	sdkState.Ready(rondSDK)
	router, err := service.SetupRouter(log, env, opa, oas, sdkState, nil, registry)
	require.NoError(t, err, "unexpected error")

	t.Run("metrics API exposed correctly", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/-/rond/metrics", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)

		responseBody := getResponseBody(t, w)
		require.Contains(t, string(responseBody), fmt.Sprintf("rond_%s", metrics.PolicyEvalDurationMetricName))
	})
}

func getResponseBody(t *testing.T, w *httptest.ResponseRecorder) []byte {
	t.Helper()

	responseBody, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)

	return responseBody
}

func TestEntrypoint(t *testing.T) {
	t.Run("start server on port 3000 and close with graceful shutdown", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		defer gock.DisableNetworking()
		gock.EnableNetworking()
		gock.NetworkingFilter(func(r *http.Request) bool {
			return r.URL.Path != "/documentation/json"
		})
		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		envs := getEnvs(t, map[string]string{
			"HTTP_PORT":               "3000",
			"TARGET_SERVICE_HOST":     "localhost:3001",
			"TARGET_SERVICE_OAS_PATH": "/documentation/json",
			"DELAY_SHUTDOWN_SECONDS":  "3",
			"OPA_MODULES_DIRECTORY":   "./mocks/rego-policies",
			"LOG_LEVEL":               "fatal",
		})
		shutdown := make(chan os.Signal, 1)
		done := make(chan bool, 1)

		go func() {
			time.Sleep(5 * time.Second)
			done <- false
		}()

		go func() {
			entrypoint(shutdown, envs)
			done <- true
		}()
		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:3000/-/rbac-ready")
		require.NoError(t, err)
		require.Equal(t, 200, resp.StatusCode)

		shutdown <- syscall.SIGTERM

		flag := <-done
		require.Equal(t, true, flag)
	})
}
