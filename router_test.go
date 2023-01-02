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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"testing"

	"github.com/mia-platform/glogger/v2"
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/foo":             openapi.PathVerbs{},
				"/bar":             openapi.PathVerbs{},
				"/foo/bar":         openapi.PathVerbs{},
				"/-/ready":         openapi.PathVerbs{},
				"/-/healthz":       openapi.PathVerbs{},
				"/-/check-up":      openapi.PathVerbs{},
				"/-/metrics":       openapi.PathVerbs{},
				"/-/rond/metrics":  openapi.PathVerbs{},
				"/-/rbac-healthz":  openapi.PathVerbs{},
				"/-/rbac-ready":    openapi.PathVerbs{},
				"/-/rbac-check-up": openapi.PathVerbs{},
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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/-/ready":    openapi.PathVerbs{},
				"/-/healthz":  openapi.PathVerbs{},
				"/-/check-up": openapi.PathVerbs{},
				// General route
				"/foo/*":          openapi.PathVerbs{},
				"/foo/bar/*":      openapi.PathVerbs{},
				"/foo/bar/nested": openapi.PathVerbs{},
				"/foo/bar/:barId": openapi.PathVerbs{},
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
		oas := &openapi.OpenAPISpec{
			Paths: openapi.OpenAPIPaths{
				"/documentation/json": openapi.PathVerbs{},
				"/foo/*":              openapi.PathVerbs{},
				"/foo/bar/*":          openapi.PathVerbs{},
				"/foo/bar/nested":     openapi.PathVerbs{},
				"/foo/bar/:barId":     openapi.PathVerbs{},
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
	mongoClient *mocks.MongoClientMock,
	permission *openapi.RondConfig,
	opaModuleConfig *core.OPAModuleConfig,
	partialResultEvaluators core.PartialResultsEvaluators,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, config.EnvKey{}, env)
	partialContext = context.WithValue(partialContext, openapi.XPermissionKey{}, permission)
	partialContext = context.WithValue(partialContext, core.OPAModuleConfigKey{}, opaModuleConfig)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}
	partialContext = context.WithValue(partialContext, core.PartialResultsEvaluatorConfigKey{}, partialResultEvaluators)

	log, _ := test.NewNullLogger()
	partialContext = glogger.WithLogger(partialContext, logrus.NewEntry(log))

	partialContext = context.WithValue(partialContext, openapi.RouterInfoKey{}, openapi.RouterInfo{
		MatchedPath:   "/matched/path",
		RequestedPath: "/requested/path",
		Method:        "GET",
	})

	partialContext = metrics.WithValue(partialContext, metrics.SetupMetrics("test_rond"))

	return partialContext
}

var mockOPAModule = &core.OPAModuleConfig{
	Name: "example.rego",
	Content: `package policies
todo { true }`,
}
var mockXPermission = &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}

var mockRondConfigWithQueryGen = &openapi.RondConfig{
	RequestFlow: openapi.RequestFlow{
		PolicyName:    "allow",
		GenerateQuery: true,
		QueryOptions: openapi.QueryOptions{
			HeaderName: "rowfilterquery",
		},
	},
}

func TestSetupRoutesIntegration(t *testing.T) {
	envs := config.EnvironmentVariables{}
	oas := prepareOASFromFile(t, "./mocks/simplifiedMock.json")

	log, _ := test.NewNullLogger()
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

	mockPartialEvaluators, _ := core.SetupEvaluators(ctx, nil, oas, mockOPAModule, envs)
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
		var mockOPAModule = &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		todo { false }`,
		}
		mockPartialEvaluators, _ := core.SetupEvaluators(ctx, nil, oas, mockOPAModule, envs)
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

		var mockOPAModule = &core.OPAModuleConfig{
			Content: "FAILING POLICY!!!!",
		}
		mockPartialEvaluators, _ := core.SetupEvaluators(ctx, nil, oas, mockOPAModule, envs)

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

func TestOPAMiddleware(t *testing.T) {
	var envs = config.EnvironmentVariables{}
	var partialEvaluators = core.PartialResultsEvaluators{}

	t.Run(`strict mode failure`, func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
todo { true }`,
		}
		var openAPISpec *openapi.OpenAPISpec
		openAPISpecContent, _ := os.ReadFile("./mocks/simplifiedMock.json")
		_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)

		t.Run(`missing oas paths`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/not-existing-path", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Result().StatusCode, "Unexpected status code.")
			require.Equal(t, &types.RequestError{
				Message:    "The request doesn't match any known API",
				Error:      "not found oas definition: GET /not-existing-path",
				StatusCode: http.StatusNotFound,
			}, getJSONResponseBody[types.RequestError](t, w))
			require.Equal(t, utils.JSONContentTypeHeader, w.Result().Header.Get(utils.ContentTypeHeaderKey), "Unexpected content type.")
		})

		t.Run(`missing method`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodDelete, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Result().StatusCode, "Unexpected status code.")
			require.Equal(t, &types.RequestError{
				Message:    "The request doesn't match any known API",
				Error:      "not found oas definition: DELETE /users/",
				StatusCode: http.StatusNotFound,
			}, getJSONResponseBody[types.RequestError](t, w))
			require.Equal(t, utils.JSONContentTypeHeader, w.Result().Header.Get(utils.ContentTypeHeaderKey), "Unexpected content type.")
		})

		t.Run(`missing permission`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com/no-permission", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
		})
	})

	t.Run(`documentation request`, func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
foobar { true }`,
		}

		t.Run(`ok - path is known on oas with no permission declared`, func(t *testing.T) {
			openAPISpec, err := openapi.LoadOASFile("./mocks/documentationPathMock.json")
			require.NoError(t, err)
			var envs = config.EnvironmentVariables{
				TargetServiceOASPath: "/documentation/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`ok - path is missing on oas and request is equal to serviceTargetOASPath`, func(t *testing.T) {
			openAPISpec, err := openapi.LoadOASFile("./mocks/simplifiedMock.json")
			require.NoError(t, err)
			var envs = config.EnvironmentVariables{
				TargetServiceOASPath: "/documentation/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`ok - path is NOT known on oas but is proxied anyway`, func(t *testing.T) {
			openAPISpec, err := openapi.LoadOASFile("./mocks/simplifiedMock.json")
			require.NoError(t, err)
			var envs = config.EnvironmentVariables{
				TargetServiceOASPath: "/documentation/custom/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/custom/json", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})
	})

	t.Run(`injects opa instance with correct query`, func(t *testing.T) {
		openAPISpec, err := openapi.LoadOASFile("./mocks/simplifiedMock.json")
		require.NoError(t, err)

		t.Run(`rego package doesn't contain expected permission`, func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
todo { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := openapi.GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, permission, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}})
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`rego package contains expected permission`, func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
foobar { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := openapi.GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}, permission)
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`rego package contains composed permission`, func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
very_very_composed_permission { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := openapi.GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "very.very.composed.permission"}}, permission)
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("injects correct permission", func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
very_very_composed_permission_with_eval { true }`,
			}

			envs := config.EnvironmentVariables{
				Standalone:           false,
				PathPrefixStandalone: "/eval", // default value
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := openapi.GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "very.very.composed.permission.with.eval"}}, permission)
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})
	})
}

func TestOPAMiddlewareStandaloneIntegration(t *testing.T) {
	openAPISpec, err := openapi.LoadOASFile("./mocks/simplifiedMock.json")
	require.Nil(t, err)

	envs := config.EnvironmentVariables{
		Standalone:           true,
		PathPrefixStandalone: "/eval", // default value
	}
	var partialEvaluators = core.PartialResultsEvaluators{}

	t.Run("injects correct path removing prefix", func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
			very_very_composed_permission { true }`,
		}

		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission, err := openapi.GetXPermission(r.Context())
			require.True(t, err == nil, "Unexpected error")
			require.Equal(t, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "very.very.composed.permission"}}, permission)
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/composed/permission/", nil)
		builtHandler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("injects correct path removing only one prefix", func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
very_very_composed_permission_with_eval { true }`,
		}

		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission, err := openapi.GetXPermission(r.Context())
			require.True(t, err == nil, "Unexpected error")
			require.Equal(t, &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "very.very.composed.permission.with.eval"}}, permission)
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/eval/composed/permission/", nil)
		builtHandler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
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

func getJSONResponseBody[T any](t *testing.T, w *httptest.ResponseRecorder) *T {
	t.Helper()

	responseBody := getResponseBody(t, w)
	out := new(T)
	if err := json.Unmarshal(responseBody, out); err != nil {
		require.Error(t, err, "fails to unmarshal")
	}
	return out
}
