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

package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestStatusRoutes(t *testing.T) {
	testRouter := mux.NewRouter()
	serviceName := "my-service-name"
	serviceVersion := "0.0.0"

	rondSDK, err := sdk.NewFromOAS(context.Background(), opa, oas, &sdk.Options{})
	require.NoError(t, err, "unexpected error")
	sdkState := NewSDKBootState()
	sdkState.Ready(rondSDK)

	StatusRoutes(testRouter, sdkState, serviceName, serviceVersion)

	t.Run("/-/rbac-healthz - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-healthz request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := io.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})

	t.Run("/-/rbac-ready - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-ready request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := io.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})

	t.Run("/-/rbac-ready - ko if sdk not ready", func(t *testing.T) {
		testRouter := mux.NewRouter()
		sdkState := NewSDKBootState()

		StatusRoutes(testRouter, sdkState, serviceName, serviceVersion)

		expectedResponse := fmt.Sprintf("{\"status\":\"KO\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-ready request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusServiceUnavailable, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := io.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})

	t.Run("/-/rbac-check-up - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-check-up request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := io.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})
}

func TestStatusRoutesIntegration(t *testing.T) {
	log, _ := test.NewNullLogger()

	rondSDK, err := sdk.NewFromOAS(context.Background(), opa, oas, &sdk.Options{})
	require.NoError(t, err, "unexpected error")

	t.Run("non standalone", func(t *testing.T) {
		sdkState := NewSDKBootState()
		sdkState.Ready(rondSDK)
		env := config.EnvironmentVariables{
			Standalone:           false,
			TargetServiceHost:    "my-service:4444",
			PathPrefixStandalone: "/my-prefix",
		}
		router, err := SetupRouter(log, env, opa, oas, sdkState, nil, nil)
		require.NoError(t, err, "unexpected error")

		t.Run("/-/rbac-ready", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-healthz", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-check-up", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})

	t.Run("standalone", func(t *testing.T) {
		sdkState := NewSDKBootState()
		sdkState.Ready(rondSDK)
		env := config.EnvironmentVariables{
			Standalone:           true,
			TargetServiceHost:    "my-service:4444",
			PathPrefixStandalone: "/my-prefix",
			ServiceVersion:       "latest",
		}
		router, err := SetupRouter(log, env, opa, oas, sdkState, nil, nil)
		require.NoError(t, err, "unexpected error")
		t.Run("/-/rbac-ready", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-healthz", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-check-up", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})
}

var opa = &core.OPAModuleConfig{
	Name: "policies",
	Content: `package policies
test_policy { true }
`,
}

var oas = &openapi.OpenAPISpec{
	Paths: openapi.OpenAPIPaths{
		"/evalapi": openapi.PathVerbs{
			"get": openapi.VerbConfig{
				PermissionV1: &openapi.XPermission{
					AllowPermission: "test_policy",
				},
			},
		},
	},
}
