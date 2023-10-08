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

	"github.com/prometheus/client_golang/prometheus"
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

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"gopkg.in/h2non/gock.v1"
)

func TestProxyOASPath(t *testing.T) {
	t.Run("200 - without oas documentation api defined", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/custom/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		resp, err := http.DefaultClient.Get("http://localhost:3000/custom/documentation/json")

		require.NoError(t, err, "error calling docs")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, gock.IsDone(), "the proxy does not blocks the request for documentations path.")
	})

	t.Run("200 - with oas documentation api defined", func(t *testing.T) {

		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3007"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3006"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})
		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3009"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3008"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})
		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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
		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/empty-dir"},
			{name: "LOG_LEVEL", value: "fatal"},
		})
		shutdown := make(chan os.Signal, 1)

		entrypoint(shutdown)
		require.True(t, true, "If we get here the service has not started")
	})

	t.Run("opens server on port 3000", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			shutdown <- syscall.SIGTERM
		}()

		time.Sleep(1 * time.Second)
		resp, err := http.DefaultClient.Get("http://localhost:3000/-/rbac-ready")
		require.Equal(t, nil, err)
		require.Equal(t, 200, resp.StatusCode)
	})

	t.Run("GracefulShutdown works properly", func(t *testing.T) {
		defer gock.Off()
		defer gock.DisableNetworkingFilters()
		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "DELAY_SHUTDOWN_SECONDS", value: "3"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
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
	})

	t.Run("opa integration", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3000"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3001"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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

		t.Run("ok - user assertions", func(t *testing.T) {
			gock.Flush()

			gock.New("http://localhost:3001/").
				Get("/assert-user").
				Reply(200)

			req, err := http.NewRequest(http.MethodGet, "http://localhost:3000/assert-user", nil)
			require.Nil(t, err)
			req.Header.Set("miauserid", "the-user-id")

			resp, err := http.DefaultClient.Do(req)
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3026"},
			{name: "LOG_LEVEL", value: "fatal"},
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3005"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3004"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3333"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:4000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/nestedPathsConfig.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "5555"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "5556"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		resp, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5556%s", path), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path with nested routes with pathParams access with escaped value", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "5557"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:6000"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/mockForEncodedTest.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

		gock.New("http://localhost:6000").
			Post(decodedPath).
			Reply(200)

		resp, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5557%s", path), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "unexpected status code.")
		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("api permissions file path registered with and without trailing slash when ignoreTrailingSlash is true", func(t *testing.T) {
		gock.Flush()
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "5559"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3339"},
			{name: "API_PERMISSIONS_FILE_PATH", value: "./mocks/nestedPathsConfig.json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)

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

		resp1, err := http.DefaultClient.Get(fmt.Sprintf("http://localhost:5559%s", "/with/trailing/slash/"))
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp1.StatusCode, "unexpected status code.")

		respBody1, _ := io.ReadAll(resp1.Body)
		require.Equal(t, "\"/with/trailing/slash/\"", string(respBody1))

		resp2, err := http.DefaultClient.Get(fmt.Sprintf("http://localhost:5559%s", "/with/trailing/slash"))
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp2.StatusCode, "unexpected status code.")

		respBody2, _ := io.ReadAll(resp2.Body)
		require.Equal(t, "\"/with/trailing/slash\"", string(respBody2))

		resp3, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5559%s", "/without/trailing/slash"), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp3.StatusCode, "unexpected status code.")

		resp4, err := http.DefaultClient.Post(fmt.Sprintf("http://localhost:5559%s", "/without/trailing/slash/"), "application/json", nil)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp4.StatusCode, "unexpected status code.")

		resp5, err := http.DefaultClient.Get(fmt.Sprintf("http://localhost:5559%s", "/ignore/trailing/slash/"))
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp5.StatusCode, "unexpected status code.")

		respBody5, _ := io.ReadAll(resp5.Body)
		require.Equal(t, "\"/ignore/trailing/slash/\"", string(respBody5))

		resp6, err := http.DefaultClient.Get(fmt.Sprintf("http://localhost:5559%s", "/ignore/trailing/slash"))
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp6.StatusCode, "unexpected status code.")

		respBody6, _ := io.ReadAll(resp6.Body)
		require.Equal(t, "\"/ignore/trailing/slash\"", string(respBody6))

		require.True(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
	})

	t.Run("mongo integration", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3003"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3002"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies-with-mongo-builtins"},
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "fatal"},
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
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
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
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
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
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)

			require.Equal(t, nil, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	})

	t.Run("200 - integration passed with query generation", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3034"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3033"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "fatal"},
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

	t.Run("200 - integration passed with x-rond configuration in oas", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "5034"},
			{name: "LOG_LEVEL", value: "fatal"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:5033"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "fatal"},
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
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:5033/users/").
			Get("/users/").
			MatchHeader("x-query-header", `{"$or":[{"$and":[{"name":{"$eq":"jane"}}]}]}`).
			Reply(200).
			JSON(map[string]interface{}{"originalMsg": "this is the original"})
		req, err := http.NewRequest("GET", "http://localhost:5034/users/", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.Equal(t, nil, err)

		require.Equal(t, `{"msg":"hey there"}`, string(bodyBytes))
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("403 - integration not passed with query generation and without user authenticated", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3036"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3035"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
			{name: "LOG_LEVEL", value: "fatal"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
			t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "fatal"},
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

	t.Run("200 - test correcting routing", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3039"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3038"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "trace"},
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
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Get("/foo/count").
			Reply(200)
		req, err := http.NewRequest("GET", "http://localhost:3039/foo/count", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("200 - test correcting routing inverted oas", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3060"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3038"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "trace"},
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
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Get("/foo/count").
			Reply(200)
		req, err := http.NewRequest("GET", "http://localhost:3060/foo/count", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("200 - test correcting routing with pathParameters", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3070"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3038"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "trace"},
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
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3038/foo/count").
			Patch("/foo/count").
			Reply(200)
		req, err := http.NewRequest("PATCH", "http://localhost:3070/foo/count", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("200 - test correcting routing with pathParameters on compex OAS", func(t *testing.T) {
		shutdown := make(chan os.Signal, 1)

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

		setEnvs(t, []env{
			{name: "HTTP_PORT", value: "3044"},
			{name: "TARGET_SERVICE_HOST", value: "localhost:3043"},
			{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
			{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		})
		mongoHost := os.Getenv("MONGO_HOST_CI")
		if mongoHost == "" {
			mongoHost = testutils.LocalhostMongoDB
		}
		randomizedDBNamePart := testutils.GetRandomName(10)
		mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

		setEnvs(t, []env{
			{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
			{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
			{name: "ROLES_COLLECTION_NAME", value: "roles"},
			{name: "LOG_LEVEL", value: "trace"},
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
			shutdown <- syscall.SIGTERM
		}()
		time.Sleep(1 * time.Second)
		gock.Flush()
		gock.New("http://localhost:3043").
			Get("/api/restaurants/1234").
			Reply(200)
		req, err := http.NewRequest("GET", "http://localhost:3044/api/restaurants/1234", nil)
		require.NoError(t, err)

		req.Header.Set("miausergroups", "group1")
		req.Header.Set("miauserid", "filter_test")
		client1 := &http.Client{}
		resp, err := client1.Do(req)
		require.Equal(t, nil, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestEntrypointWithResponseFiltering(t *testing.T) {
	shutdown := make(chan os.Signal, 1)

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

	setEnvs(t, []env{
		{name: "HTTP_PORT", value: "3041"},
		{name: "TARGET_SERVICE_HOST", value: "localhost:3040"},
		{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
		{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		{name: "LOG_LEVEL", value: "fatal"},
	})
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	setEnvs(t, []env{
		{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
		{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
		{name: "ROLES_COLLECTION_NAME", value: "roles"},
		{name: "LOG_LEVEL", value: "fatal"},
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
		respBody, _ := io.ReadAll(resp.Body)
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
		respBody, _ := io.ReadAll(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, `{"FT_1":true}`, string(respBody))
	})
}

type env struct {
	name  string
	value string
}

func setEnvs(t *testing.T, envsToSet []env) {
	for _, env := range envsToSet {
		t.Setenv(env.name, env.value)
	}
}

func TestIntegrationWithOASParamsInBrackets(t *testing.T) {
	shutdown := make(chan os.Signal, 1)

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

	setEnvs(t, []env{
		{name: "HTTP_PORT", value: "3051"},
		{name: "TARGET_SERVICE_HOST", value: "localhost:3050"},
		{name: "TARGET_SERVICE_OAS_PATH", value: "/documentation/json"},
		{name: "OPA_MODULES_DIRECTORY", value: "./mocks/rego-policies"},
		{name: "LOG_LEVEL", value: "fatal"},
	})
	mongoHost := os.Getenv("MONGO_HOST_CI")
	if mongoHost == "" {
		mongoHost = testutils.LocalhostMongoDB
		t.Logf("Connection to localhost MongoDB, on CI env this is a problem!")
	}
	randomizedDBNamePart := testutils.GetRandomName(10)
	mongoDBName := fmt.Sprintf("test-%s", randomizedDBNamePart)

	setEnvs(t, []env{
		{name: "MONGODB_URL", value: fmt.Sprintf("mongodb://%s/%s", mongoHost, mongoDBName)},
		{name: "BINDINGS_COLLECTION_NAME", value: "bindings"},
		{name: "ROLES_COLLECTION_NAME", value: "roles"},
		{name: "LOG_LEVEL", value: "fatal"},
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
	opa := &core.OPAModuleConfig{
		Name: "policies",
		Content: `package policies
test_policy { true }

filter_policy {
	query := data.resources[_]
	query.answer = 42
}
`,
	}
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
	router, completionChan := service.SetupRouter(log, env, opa, oas, sdkState, nil, nil)
	err = <-completionChan
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
	opa := &core.OPAModuleConfig{
		Name: "policies",
		Content: `package policies
test_policy { true }

filter_policy {
	query := data.resources[_]
	query.answer = 42
}
`,
	}
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
	router, completionChan := service.SetupRouter(log, env, opa, oas, sdkState, nil, registry)
	err = <-completionChan
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
