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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/mia-platform/glogger/v2"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/gorilla/mux"
)

func TestSetupRoutes(t *testing.T) {
	envs := config.EnvironmentVariables{
		TargetServiceOASPath: "/documentation/json",
	}
	t.Run("expect to register route correctly", func(t *testing.T) {
		router := mux.NewRouter()
		oas := &OpenAPISpec{
			Paths: OpenAPIPaths{
				"/foo":             PathVerbs{},
				"/bar":             PathVerbs{},
				"/foo/bar":         PathVerbs{},
				"/-/ready":         PathVerbs{},
				"/-/healthz":       PathVerbs{},
				"/-/check-up":      PathVerbs{},
				"/-/metrics":       PathVerbs{},
				"/-/rond/metrics":  PathVerbs{},
				"/-/rbac-healthz":  PathVerbs{},
				"/-/rbac-ready":    PathVerbs{},
				"/-/rbac-check-up": PathVerbs{},
			},
		}
		expectedPaths := []string{"/", "/-/check-up", "/-/healthz", "/-/metrics", "/-/ready", "/bar", "/documentation/json", "/foo", "/foo/bar"}

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		require.Equal(t, expectedPaths, foundPaths)
	})

	t.Run("expect to register nested route correctly", func(t *testing.T) {
		router := mux.NewRouter()
		oas := &OpenAPISpec{
			Paths: OpenAPIPaths{
				"/-/ready":    PathVerbs{},
				"/-/healthz":  PathVerbs{},
				"/-/check-up": PathVerbs{},
				// General route
				"/foo/*":          PathVerbs{},
				"/foo/bar/*":      PathVerbs{},
				"/foo/bar/nested": PathVerbs{},
				"/foo/bar/:barId": PathVerbs{},
			},
		}
		expectedPaths := []string{"/", "/-/ready", "/-/healthz", "/-/check-up", "/foo/", "/foo/bar/", "/foo/bar/nested", "/foo/bar/{barId}", "/documentation/json"}
		sort.Strings(expectedPaths)

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		require.Equal(t, expectedPaths, foundPaths)
	})

	t.Run("expect to register route correctly in standalone mode", func(t *testing.T) {
		envs := config.EnvironmentVariables{
			TargetServiceOASPath: "/documentation/json",
			Standalone:           true,
			PathPrefixStandalone: "/validate",
		}
		router := mux.NewRouter()
		oas := &OpenAPISpec{
			Paths: OpenAPIPaths{
				"/documentation/json": PathVerbs{},
				"/foo/*":              PathVerbs{},
				"/foo/bar/*":          PathVerbs{},
				"/foo/bar/nested":     PathVerbs{},
				"/foo/bar/:barId":     PathVerbs{},
			},
		}
		expectedPaths := []string{"/validate/", "/validate/documentation/json", "/validate/foo/", "/validate/foo/bar/", "/validate/foo/bar/nested", "/validate/foo/bar/{barId}"}
		sort.Strings(expectedPaths)

		setupRoutes(router, oas, envs)

		foundPaths := make([]string, 0)
		router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			path, err := route.GetPathTemplate()
			if err != nil {
				t.Fatalf("Unexpected error during walk: %s", err.Error())
			}

			foundPaths = append(foundPaths, path)
			return nil
		})
		sort.Strings(foundPaths)

		require.Equal(t, expectedPaths, foundPaths)
	})
}

func TestConvertPathVariables(t *testing.T) {
	listOfPaths := []struct {
		Path          string
		ConvertedPath string
	}{
		{Path: "/", ConvertedPath: "/"},
		{Path: "/endpoint-1", ConvertedPath: "/endpoint-1"},
		{Path: "/endpoint-1/:id", ConvertedPath: "/endpoint-1/{id}"},
		{Path: "/endpoint-1/:id/", ConvertedPath: "/endpoint-1/{id}/"},
		{Path: "/endpoint-1/:id1/:id2/:id3", ConvertedPath: "/endpoint-1/{id1}/{id2}/{id3}"},
		{Path: "/endpoint-1/", ConvertedPath: "/endpoint-1/"},
		{Path: "/endpoint-1/:id/upsert", ConvertedPath: "/endpoint-1/{id}/upsert"},
		{Path: "/external-endpoint/:id", ConvertedPath: "/external-endpoint/{id}"},
		{Path: "/:another/external-endpoint", ConvertedPath: "/{another}/external-endpoint"},
	}

	t.Run("convert correctly paths", func(t *testing.T) {
		for _, path := range listOfPaths {
			convertedPath := convertPathVariablesToBrackets(path.Path)
			require.Equal(t, path.ConvertedPath, convertedPath, "Path not converted correctly.")
		}
	})
}

func TestConvertPathVariables2(t *testing.T) {
	listOfPaths := []struct {
		Path          string
		ConvertedPath string
	}{
		{Path: "/", ConvertedPath: "/"},
		{Path: "/endpoint-1", ConvertedPath: "/endpoint-1"},
		{Path: "/endpoint-1/", ConvertedPath: "/endpoint-1/"},
		{Path: "/endpoint-1/{id}", ConvertedPath: "/endpoint-1/:id"},
		{Path: "/endpoint-1/{id}/", ConvertedPath: "/endpoint-1/:id/"},
		{Path: "/endpoint-1/{id1}/{id2}/{id3}", ConvertedPath: "/endpoint-1/:id1/:id2/:id3"},
		{Path: "/endpoint-1/{id}/upsert", ConvertedPath: "/endpoint-1/:id/upsert"},
		{Path: "/:another/external-endpoint", ConvertedPath: "/:another/external-endpoint"},
	}

	t.Run("convert correctly paths", func(t *testing.T) {
		for _, path := range listOfPaths {
			convertedPath := convertPathVariablesToColons(path.Path)
			require.Equal(t, path.ConvertedPath, convertedPath, "Path not converted correctly.")
		}
	})
}

func createContext(
	t *testing.T,
	originalCtx context.Context,
	env config.EnvironmentVariables,
	mongoClient *mocks.MongoClientMock,
	permission *RondConfig,
	opaModuleConfig *OPAModuleConfig,
	partialResultEvaluators PartialResultsEvaluators,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, config.EnvKey{}, env)
	partialContext = context.WithValue(partialContext, XPermissionKey{}, permission)
	partialContext = context.WithValue(partialContext, OPAModuleConfigKey{}, opaModuleConfig)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}
	partialContext = context.WithValue(partialContext, PartialResultsEvaluatorConfigKey{}, partialResultEvaluators)

	log, _ := test.NewNullLogger()
	partialContext = glogger.WithLogger(partialContext, logrus.NewEntry(log))

	partialContext = context.WithValue(partialContext, RouterInfoKey{}, RouterInfo{
		MatchedPath:   "/matched/path",
		RequestedPath: "/requested/path",
		Method:        "GET",
	})

	partialContext = metrics.WithValue(partialContext, metrics.SetupMetrics("test_rond"))

	return partialContext
}

var mockOPAModule = &OPAModuleConfig{
	Name: "example.rego",
	Content: `package policies
todo { true }`,
}
var mockXPermission = &RondConfig{RequestFlow: RequestFlow{PolicyName: "todo"}}

var mockRondConfigWithQueryGen = &RondConfig{
	RequestFlow: RequestFlow{
		PolicyName:    "allow",
		GenerateQuery: true,
		QueryOptions: QueryOptions{
			HeaderName: "rowfilterquery",
		},
	},
}

func TestSetupRoutesIntegration(t *testing.T) {
	oas := prepareOASFromFile(t, "./mocks/simplifiedMock.json")

	log, _ := test.NewNullLogger()
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

	mockPartialEvaluators, _ := setupEvaluators(ctx, nil, oas, mockOPAModule, envs)
	t.Run("invokes known API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			require.Equal(t, "/users/", r.URL.Path, "Mocked Backend: Unexpected path of request url")
			require.Equal(t, "foo=bar", r.URL.RawQuery, "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.True(t, invoked, "mock server was not invoked")
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("invokes unknown API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			require.Equal(t, "/unknown/path", r.URL.Path, "Mocked Backend: Unexpected path of request url")
			require.Equal(t, "foo=bar", r.URL.RawQuery, "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/unknown/path?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.True(t, invoked, "mock server was not invoked")
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("blocks request on not allowed policy evaluation", func(t *testing.T) {
		var mockOPAModule = &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		todo { false }`,
		}
		mockPartialEvaluators, _ := setupEvaluators(ctx, nil, oas, mockOPAModule, envs)
		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		ctx := createContext(t,
			ctx,
			config.EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("blocks request on policy evaluation error", func(t *testing.T) {

		var mockOPAModule = &OPAModuleConfig{
			Content: "FAILING POLICY!!!!",
		}
		mockPartialEvaluators, _ := setupEvaluators(ctx, nil, oas, mockOPAModule, envs)

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/users/?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)
	})

	t.Run("invokes the API not explicitly set in the oas file", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/nestedPathsConfig.json")

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/foo/route-not-registered-explicitly", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.True(t, invoked, "mock server was not invoked")
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})

	t.Run("invokes a specific API within a nested path", func(t *testing.T) {
		oas := prepareOASFromFile(t, "./mocks/nestedPathsConfig.json")

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/foo/bar/nested", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.True(t, invoked, "mock server was not invoked")
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestRoutesToNotProxy(t *testing.T) {
	require.Equal(t, routesToNotProxy, []string{"/-/rbac-healthz", "/-/rbac-ready", "/-/rbac-check-up", "/-/rond/metrics"})
}

func prepareOASFromFile(t *testing.T, filePath string) *OpenAPISpec {
	t.Helper()

	oas, err := loadOASFile(filePath)
	require.NoError(t, err)
	return oas
}
