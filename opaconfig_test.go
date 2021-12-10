package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

var envs = EnvironmentVariables{}

func TestOPAMiddleware(t *testing.T) {
	t.Run(`strict mode failure`, func(t *testing.T) {
		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
todo { true }`,
		}
		var openAPISpec *OpenAPISpec
		openAPISpecContent, _ := ioutil.ReadFile("./mocks/simplifiedMock.json")
		_ = json.Unmarshal(openAPISpecContent, &openAPISpec)

		middleware := OPAMiddleware(opaModule, openAPISpec, &envs)

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

	t.Run(`documentation request`, func(t *testing.T) {
		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
foobar { true }`,
		}

		t.Run(`ko - path is known on oas`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/documentationPathMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
			var envs = EnvironmentVariables{
				TargetServiceOASPath: "/documentation/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})

		t.Run(`ok - path is known on oas`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/documentationPathMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
			var envs = EnvironmentVariables{
				TargetServiceOASPath: "/documentation/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`ok - path is missing on oas and request is equal to serviceTargetOASPath`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/simplifiedMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
			var envs = EnvironmentVariables{
				TargetServiceOASPath: "/documentation/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				evaluator := r.Context().Value(OPAEvaluatorKey{}).(*OPAEvaluator)
				evaluatorType := reflect.TypeOf(evaluator.PermissionQuery)
				trustyEvaluator := reflect.TypeOf(&TruthyEvaluator{})
				assert.Equal(t, evaluatorType, trustyEvaluator, "Unexpected evaluator type")
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`ko - path is NOT known on oas`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/simplifiedMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
			var envs = EnvironmentVariables{
				TargetServiceOASPath: "/documentation/custom/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
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
				Content: `package policies
todo { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input := map[string]interface{}{}
				opaEvaluator, err := GetOPAEvaluator(r.Context())
				require.True(t, err == nil, "Unexpected error")
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
				Content: `package policies
foobar { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
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

		t.Run(`rego package contains composed permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
very_very_composed_permission { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input := map[string]interface{}{}
				opaEvaluator, _ := GetOPAEvaluator(r.Context())
				results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
				require.Equal(t, nil, err, "unexpected error")
				require.True(t, results.Allowed(), "unexpected allow")

				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`rego package contains composed permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package example
very_very_composed_permission { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				input := map[string]interface{}{}
				opaEvaluator, _ := GetOPAEvaluator(r.Context())
				results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
				require.Equal(t, nil, err, "unexpected error")
				require.True(t, results.Allowed(), "unexpected allow")

				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})
	})
}

func TestGetHeaderFunction(t *testing.T) {
	headerKeyMocked := "exampleKey"
	headerValueMocked := "value"

	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		todo { get_header("ExAmPlEkEy", input.headers) == "value" }`,
	}
	queryString := "todo"

	opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
	assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

	t.Run("if header key exists", func(t *testing.T) {
		headers := http.Header{}
		headers.Add(headerKeyMocked, headerValueMocked)
		input := map[string]interface{}{
			"headers": headers,
		}

		results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, results.Allowed(), "The input is not allowed by rego")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}

		results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, !results.Allowed(), "Rego policy allows illegal input")
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
