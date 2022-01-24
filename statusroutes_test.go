package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
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
