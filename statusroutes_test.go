package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mongoclient"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestStatusRoutes(testCase *testing.T) {
	testRouter := mux.NewRouter()
	serviceName := "my-service-name"
	serviceVersion := "0.0.0"
	StatusRoutes(testRouter, serviceName, serviceVersion)

	testCase.Run("/-/rbac-healthz - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-healthz request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := ioutil.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})

	testCase.Run("/-/rbac-ready - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-ready request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := ioutil.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})

	testCase.Run("/-/rbac-check-up - ok", func(t *testing.T) {
		expectedResponse := fmt.Sprintf("{\"status\":\"OK\",\"name\":\"%s\",\"version\":\"%s\"}", serviceName, serviceVersion)
		responseRecorder := httptest.NewRecorder()
		request, requestError := http.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
		require.NoError(t, requestError, "Error creating the /-/rbac-check-up request")

		testRouter.ServeHTTP(responseRecorder, request)
		statusCode := responseRecorder.Result().StatusCode
		require.Equal(t, http.StatusOK, statusCode, "The response statusCode should be 200")

		rawBody := responseRecorder.Result().Body
		body, readBodyError := ioutil.ReadAll(rawBody)
		require.NoError(t, readBodyError)
		require.Equal(t, expectedResponse, string(body), "The response body should be the expected one")
	})
}

func TestStatusRoutesIntegration(t *testing.T) {
	log, _ := test.NewNullLogger()
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
	evaluatorsMap, err := setupEvaluators(context.TODO(), mongoClient, oas, opa, envs)
	assert.NilError(t, err, "unexpected error")

	t.Run("non standalone", func(t *testing.T) {
		env := config.EnvironmentVariables{
			Standalone:           false,
			TargetServiceHost:    "my-service:4444",
			PathPrefixStandalone: "/my-prefix",
		}
		router, err := setupRouter(log, env, opa, oas, evaluatorsMap, mongoClient)
		assert.NilError(t, err, "unexpected error")

		t.Run("/-/rbac-ready", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-healthz", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-check-up", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})

	t.Run("standalone", func(t *testing.T) {
		env := config.EnvironmentVariables{
			Standalone:           true,
			TargetServiceHost:    "my-service:4444",
			PathPrefixStandalone: "/my-prefix",
		}
		router, err := setupRouter(log, env, opa, oas, evaluatorsMap, mongoClient)
		assert.NilError(t, err, "unexpected error")
		t.Run("/-/rbac-ready", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-ready", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-healthz", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-healthz", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
		t.Run("/-/rbac-check-up", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/-/rbac-check-up", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	})
}
