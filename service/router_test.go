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
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/evaluationdata"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/fake"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/logging"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/metrics"
	rondprometheus "github.com/rond-authz/rond/metrics/prometheus"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"

	"github.com/mia-platform/glogger/v4"
	"github.com/prometheus/client_golang/prometheus"
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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/foo":             openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/bar":             openapi.PathVerbs{"post": openapi.VerbConfig{}},
				"/foo/bar":         openapi.PathVerbs{"patch": openapi.VerbConfig{}},
				"/-/ready":         openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/healthz":       openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/check-up":      openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/metrics":       openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/rond/metrics":  openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/rbac-healthz":  openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/rbac-ready":    openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/rbac-check-up": openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/with/trailing/slash": openapi.PathVerbs{
					"get": openapi.VerbConfig{
						PermissionV2: &core.RondConfig{
							RequestFlow: core.RequestFlow{
								PolicyName: "filter_policy",
							},
							Options: core.PermissionOptions{IgnoreTrailingSlash: true},
						},
					},
				},
			},
		}
		expectedPaths := []string{
			"/",
			"/-/check-up",
			"/-/healthz",
			"/-/metrics",
			"/-/ready",
			"/bar",
			"/documentation/json",
			"/foo",
			"/foo/bar",
			"/{/with/trailing/slash:/with/trailing/slash\\/?}",
		}

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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/-/ready":    openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/healthz":  openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/-/check-up": openapi.PathVerbs{"get": openapi.VerbConfig{}},
				// General route
				"/foo/*":          openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/bar/*":      openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/bar/nested": openapi.PathVerbs{"post": openapi.VerbConfig{}},
				"/foo/bar/:barId": openapi.PathVerbs{"get": openapi.VerbConfig{}},
			},
		}
		expectedPaths := []string{
			"/",
			"/-/ready",
			"/-/healthz",
			"/-/check-up",
			"/foo/bar/nested",
			"/foo/bar/{barId}",
			"/foo/bar/",
			"/foo/",
			"/documentation/json",
		}
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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/documentation/json": openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/*":              openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/bar/*":          openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/bar/nested":     openapi.PathVerbs{"get": openapi.VerbConfig{}},
				"/foo/bar/:barId":     openapi.PathVerbs{"get": openapi.VerbConfig{}},
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
			convertedPath := openapi.ConvertPathVariablesToBrackets(path.Path)
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
			convertedPath := openapi.ConvertPathVariablesToColons(path.Path)
			require.Equal(t, path.ConvertedPath, convertedPath, "Path not converted correctly.")
		}
	})
}

func createContext(
	t *testing.T,
	originalCtx context.Context,
	env config.EnvironmentVariables,
	evaluator sdk.Evaluator,
	mongoClient *mocks.MongoClientMock,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, config.EnvKey{}, env)

	partialContext = sdk.WithEvaluator(partialContext, evaluator)

	if mongoClient != nil {
		partialContext = evaluationdata.WithClient(partialContext, mongoClient)
	}

	partialContext = glogger.WithLogger(partialContext, logrus.NewEntry(logrus.New()))

	return partialContext
}

var mockOPAModule = &core.OPAModuleConfig{
	Name: "example.rego",
	Content: `package policies
todo { true }`,
}
var mockXPermission = core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "todo"}}

type evaluatorParams struct {
	logger   logging.Logger
	registry *prometheus.Registry
}

func getEvaluator(
	t *testing.T,
	ctx context.Context,
	opaModule *core.OPAModuleConfig,
	mongoClient custom_builtins.IMongoClient,
	rondConfig core.RondConfig,
	oas *openapi.OpenAPISpec,
	method, path string,
	options *evaluatorParams,
) sdk.Evaluator {
	t.Helper()

	if options == nil {
		options = &evaluatorParams{}
	}

	logger := options.logger
	if logger == nil {
		log := logrus.New()
		logger = rondlogrus.NewLogger(log)
	}

	var m *metrics.Metrics
	if options.registry != nil {
		m = rondprometheus.SetupMetrics(options.registry)
	}

	sdk, err := sdk.NewFromOAS(context.Background(), opaModule, oas, &sdk.Options{
		EvaluatorOptions: &core.OPAEvaluatorOptions{
			MongoClient: mongoClient,
		},
		Logger:  logger,
		Metrics: m,
	})
	require.NoError(t, err, "unexpected error")

	evaluator, err := sdk.FindEvaluator(logger, method, path)
	require.NoError(t, err)

	return evaluator
}

func TestSetupRoutesIntegration(t *testing.T) {
	envs := config.EnvironmentVariables{}
	oas := prepareOASFromFile(t, "../mocks/simplifiedMock.json")

	log, _ := test.NewNullLogger()
	logger := rondlogrus.NewLogger(log)
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

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

		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas, http.MethodGet, "/users/", nil)

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			nil,
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
		serverURL, _ := url.Parse(server.URL)

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		eval, err := openapi.SetupEvaluators(ctx, logger, oas, mockOPAModule, nil)
		require.NoError(t, err)
		evaluator := fake.NewSDKEvaluator(eval, mockXPermission, nil)

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			nil,
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
		var mockOPAModule = &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		todo { false }`,
		}
		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas, http.MethodGet, "/users/", nil)

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			evaluator,
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, w.Body.String())
	})

	t.Run("blocks request on policy evaluation error", func(t *testing.T) {
		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		evaluator := fake.NewSDKEvaluator(nil, mockXPermission, &fake.RequestPolicyEvaluatorResult{
			Err: fmt.Errorf("fails to evaluate policy"),
		})

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			evaluator,
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/users/?foo=bar", nil)
		require.NoError(t, err, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		require.True(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	})

	t.Run("invokes the API not explicitly set in the oas file", func(t *testing.T) {
		oas := prepareOASFromFile(t, "../mocks/nestedPathsConfig.json")
		rondConfig := core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "foo"}}
		var mockOPAModule = &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		foo { true }`,
		}

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)

		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, rondConfig, oas, http.MethodGet, "/foo/route-not-registered-explicitly", nil)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			nil,
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
		oas := prepareOASFromFile(t, "../mocks/nestedPathsConfig.json")
		rondConfig := core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "foo"}}
		var mockOPAModule = &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		foo_bar_nested { true }`,
		}

		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)

		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, rondConfig, oas, http.MethodGet, "/foo/bar/nested", nil)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			nil,
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

func prepareOASFromFile(t *testing.T, filePath string) *openapi.OpenAPISpec {
	t.Helper()

	oas, err := openapi.LoadOASFile(filePath)
	require.NoError(t, err)
	return oas
}
