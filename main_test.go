/*
 * Copyright 2019 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestEntryPoint(t *testing.T) {
	t.Run("fails for invalid module path, no module found", func(t *testing.T) {
		os.Setenv("HTTP_PORT", "3000")
		os.Setenv("TARGET_SERVICE_HOST", "localhost:3001")
		os.Setenv("TARGET_SERVICE_OAS_PATH", "/documentation/json")
		os.Setenv("OPA_MODULES_DIRECTORY", "./mocks/empty-dir")

		shutdown := make(chan os.Signal, 1)

		entrypoint(shutdown)
		require.True(t, true, "If we get here the service has not started")
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

		os.Setenv("HTTP_PORT", "3000")
		os.Setenv("TARGET_SERVICE_HOST", "localhost:3001")
		os.Setenv("TARGET_SERVICE_OAS_PATH", "/documentation/json")
		os.Setenv("OPA_MODULES_DIRECTORY", "./mocks/rego-policies")

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			os.Unsetenv("HTTP_PORT")
			shutdown <- syscall.SIGTERM
		}()

		time.Sleep(1 * time.Second)
		resp, err := http.DefaultClient.Get("http://localhost:3000/-/ready")
		require.Equal(t, nil, err)
		require.Equal(t, 200, resp.StatusCode)
	})

	t.Run("GracefulShutdown works properly", func(t *testing.T) {
		defer gock.Off()
		gock.New("http://localhost:3001").
			Get("/documentation/json").
			Reply(200).
			File("./mocks/simplifiedMock.json")

		os.Setenv("HTTP_PORT", "3000")
		os.Setenv("TARGET_SERVICE_HOST", "localhost:3001")
		os.Setenv("TARGET_SERVICE_OAS_PATH", "/documentation/json")
		os.Setenv("DELAY_SHUTDOWN_SECONDS", "3")

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

		os.Setenv("HTTP_PORT", "3000")
		os.Setenv("TARGET_SERVICE_HOST", "localhost:3001")
		os.Setenv("TARGET_SERVICE_OAS_PATH", "/documentation/json")
		os.Setenv("OPA_MODULES_DIRECTORY", "./mocks/rego-policies")

		go func() {
			entrypoint(shutdown)
		}()
		defer func() {
			os.Unsetenv("HTTP_PORT")
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
			gock.New("http://localhost:3001/users/").
				Post("/users/").
				Reply(200)
			resp, err := http.DefaultClient.Post("http://localhost:3000/users/", "text/plain", nil)
			require.Equal(t, nil, err)
			require.Equal(t, http.StatusForbidden, resp.StatusCode, "unexpected status code.")
			require.False(t, gock.IsDone(), "the proxy forwards the request when the permissions aren't granted.")
		})
	})
}
