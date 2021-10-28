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

	"github.com/gorilla/mux"
	"gotest.tools/v3/assert"
)

func TestSetupRoutes(t *testing.T) {
	router := mux.NewRouter()

	oas := &OpenAPISpec{
		Paths: OpenAPIPaths{
			"/foo":     PathVerbs{},
			"/bar":     PathVerbs{},
			"/foo/bar": PathVerbs{},
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

func TestSetupRoutesIntegration(t *testing.T) {
	oas := prepareOASFromFile(t, "./mocks/crudServiceMock.json")

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
		ctx := context.WithValue(context.Background(), envKey{}, EnvironmentVariables{
			TargetServiceHost: serverURL.Host,
		})

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
		ctx := context.WithValue(context.Background(), envKey{}, EnvironmentVariables{TargetServiceHost: serverURL.Host})
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
