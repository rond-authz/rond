package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestOPAMiddleware(t *testing.T) {
	t.Run(`strict mode failure`, func(t *testing.T) {
		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package example
todo { true }`,
		}
		var openAPISpec *OpenAPISpec
		openAPISpecContent, _ := ioutil.ReadFile("./mocks/simplifiedMock.json")
		_ = json.Unmarshal(openAPISpecContent, &openAPISpec)

		middleware := OPAMiddleware(opaModule, openAPISpec)

		t.Run(`missing oas paths`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/notExistingPath", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})

		t.Run(`missing method`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodDelete, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})

		t.Run(`missing permission`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodDelete, "http://example.com/no-permission/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})
	})

	t.Run(`injects opa instance with correct query`, func(t *testing.T) {
		var openAPISpec *OpenAPISpec
		openAPISpecContent, _ := ioutil.ReadFile("./mocks/simplifiedMock.json")
		_ = json.Unmarshal(openAPISpecContent, &openAPISpec)

		t.Run(`rego package doesn't contain expected permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package example
todo { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input := map[string]interface{}{}
				opaEvaluator, _ := GetOPAEvaluator(r.Context())
				results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
				require.Equal(t, nil, err, "unexpected error")
				require.False(t, results.Allowed(), "unexpected allow")

				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`rego package contains expected permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package example
foobar { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input := map[string]interface{}{}
				opaEvaluator, _ := GetOPAEvaluator(r.Context())
				results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
				require.Equal(t, nil, err, "unexpected error")
				require.True(t, results.Allowed(), "unexpected allow")

				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})
	})
}

func TestGetOPAEvaluator(t *testing.T) {
	t.Run(`GetOPAEvaluator fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetOPAEvaluator(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetOPAEvaluator returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), OPAEvaluatorKey{}, &OPAEvaluator{})
		opaEval, err := GetOPAEvaluator(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, opaEval != nil, "localhost:3000", "Unexpected session duration seconds env variable.")
	})
}
