package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mocks"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"

	"github.com/gorilla/mux"
	"gotest.tools/v3/assert"
)

func TestSetupRoutes(t *testing.T) {
	envs := EnvironmentVariables{
		TargetServiceOASPath: "/documentation/json",
	}
	t.Run("expect to register route correctly", func(t *testing.T) {
		router := mux.NewRouter()
		oas := &OpenAPISpec{
			Paths: OpenAPIPaths{
				"/foo":        PathVerbs{},
				"/bar":        PathVerbs{},
				"/foo/bar":    PathVerbs{},
				"/-/ready":    PathVerbs{},
				"/-/healthz":  PathVerbs{},
				"/-/check-up": PathVerbs{},
			},
		}
		expectedPaths := []string{"/", "/-/check-up", "/-/healthz", "/-/ready", "/bar", "/documentation/json", "/foo", "/foo/bar"}

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

		assert.DeepEqual(t, foundPaths, expectedPaths)
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

		assert.DeepEqual(t, foundPaths, expectedPaths)
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
			convertedPath := convertPathVariables(path.Path)
			assert.Equal(t, convertedPath, path.ConvertedPath, "Path not converted correctly.")
		}
	})
}

func createContext(
	t *testing.T,
	originalCtx context.Context,
	env EnvironmentVariables,
	mongoClient *mocks.MongoClientMock,
	permission *XPermission,
	opaModuleConfig *OPAModuleConfig,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, envKey{}, env)
	partialContext = context.WithValue(partialContext, XPermissionKey{}, permission)
	partialContext = context.WithValue(partialContext, OPAModuleConfigKey{}, opaModuleConfig)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}

	return partialContext
}

func buildMockMongoClient(roles []types.Role, bindings []types.Binding) mocks.MongoClientMock {
	return mocks.MongoClientMock{}
}

var mockGetUserPermissions = buildMockMongoClient(nil, nil)

var mockOPAModule = &OPAModuleConfig{
	Name: "example.rego",
	Content: `package policies
todo { true }`,
}
var mockXPermission = &XPermission{AllowPermission: "todo"}

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
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
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
		setupRoutes(router, oas, envs)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
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
		setupRoutes(router, oas, envs)

		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{LogLevel: "silent", TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			&OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
			todo { false }`,
			},
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
		setupRoutes(router, oas, envs)

		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: "targetServiceHostWillNotBeInvoked"},
			nil,
			mockXPermission,
			&OPAModuleConfig{
				Content: "FAILING POLICY!!!!",
			},
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/users/?foo=bar", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden)
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
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://my-service.com/foo/route-not-registered-explicitly", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
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
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", "http://crud-service/foo/bar/nested", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		var matchedRouted mux.RouteMatch
		ok := router.Match(req, &matchedRouted)
		assert.Assert(t, ok, "Route not found")

		w := httptest.NewRecorder()
		matchedRouted.Handler.ServeHTTP(w, req)

		assert.Assert(t, invoked, "mock server was not invoked")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK)
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
