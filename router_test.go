package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"rbac-service/internal/mocks"
	"rbac-service/internal/types"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/rego"
	"gotest.tools/v3/assert"
)

func TestSetupRoutes(t *testing.T) {
	router := mux.NewRouter()

	oas := &OpenAPISpec{
		Paths: OpenAPIPaths{
			"/foo":     PathVerbs{},
			"/bar":     PathVerbs{},
			"/foo/bar": PathVerbs{},
			// Ignored routes
			"/-/ready":    PathVerbs{},
			"/-/healthz":  PathVerbs{},
			"/-/check-up": PathVerbs{},
		},
	}
	expectedPaths := []string{"/", "/foo", "/bar", "/foo/bar"}
	sort.Strings(expectedPaths)

	setupRoutes(router, oas)

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

	assert.DeepEqual(t, foundPaths, expectedPaths)
}

func createContext(t *testing.T, originalCtx context.Context, env EnvironmentVariables, opaEvaluator *OPAEvaluator, mongoClient *mocks.MongoClientMock) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, envKey{}, env)
	partialContext = context.WithValue(partialContext, OPAEvaluatorKey{}, opaEvaluator)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}

	return partialContext
}

func buildMockEvaluator(allowed bool) mocks.MockEvaluator {
	return mocks.MockEvaluator{
		ResultSet: rego.ResultSet{
			rego.Result{
				Expressions: []*rego.ExpressionValue{
					{Value: allowed},
				},
			},
		},
	}
}

func buildMockMongoClient(permissions []string) mocks.MongoClientMock {
	return mocks.MongoClientMock{
		UserPermissions:      permissions,
		UserPermissionsError: errors.New("can not retrieve user permissions"),
	}
}

var mockAllowedOPAEvaluator = buildMockEvaluator(true)
var mockNotAllowedOPAEvaluator = buildMockEvaluator(false)

var mockGetUserPermissions = buildMockMongoClient([]string{"permission1", "permission2"})

func TestSetupRoutesIntegration(t *testing.T) {
	oas := prepareOASFromFile(t, "./mocks/simplifiedMock.json")

	t.Run("invokes known API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.URL.Path, "/users/", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "foo=bar", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("invokes unknown API", func(t *testing.T) {
		var invoked bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.URL.Path, "/unknown/path", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "foo=bar", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		router := mux.NewRouter()
		setupRoutes(router, oas)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/unknown/path?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
	})

	t.Run("blocks request on not allowed policy evaluation", func(t *testing.T) {
		router := mux.NewRouter()
		setupRoutes(router, oas)

		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			&OPAEvaluator{PermissionQuery: &mockNotAllowedOPAEvaluator},
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden)
	})

	t.Run("blocks request on policy evaluation error", func(t *testing.T) {
		router := mux.NewRouter()
		setupRoutes(router, oas)

		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			&OPAEvaluator{PermissionQuery: &mocks.MockEvaluator{ResultError: errors.New("some error from policy eval")}},
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)
	})

	t.Run("blocks request on policy evaluation error", func(t *testing.T) {
		router := mux.NewRouter()
		setupRoutes(router, oas)

		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			&OPAEvaluator{PermissionQuery: &mocks.MockEvaluator{ResultError: errors.New("some error from policy eval")}},
			nil,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)
	})
}

func prepareOASFromFile(t *testing.T, filePath string) *OpenAPISpec {
	t.Helper()

	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	var oas OpenAPISpec
	if err := json.Unmarshal(fileContent, &oas); err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}
	return &oas
}
