package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

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
			r := httptest.NewRequest(http.MethodGet, "http://example.com/not-existing-path", nil)
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
			r := httptest.NewRequest(http.MethodPost, "http://example.com/no-permission", nil)
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

		t.Run(`ok - path is known on oas with no permission declared`, func(t *testing.T) {
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
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`ok - path is NOT known on oas but is proxied anyway`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/simplifiedMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
			var envs = EnvironmentVariables{
				TargetServiceOASPath: "/documentation/custom/json",
			}
			middleware := OPAMiddleware(opaModule, openAPISpec, &envs)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/custom/json", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
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
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, permission, &XPermission{AllowPermission: "foobar"})
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
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, permission, &XPermission{AllowPermission: "foobar"})
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
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &XPermission{AllowPermission: "very.very.composed.permission"}, permission)
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

	t.Run("if header key exists", func(t *testing.T) {
		headers := http.Header{}
		headers.Add(headerKeyMocked, headerValueMocked)
		input := map[string]interface{}{
			"headers": headers,
		}

		opaEvaluator, err := NewOPAEvaluator(queryString, opaModule, input)
		assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PermissionQuery.Eval(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, results.Allowed(), "The input is not allowed by rego")

		partialResults, err := opaEvaluator.PermissionQuery.Partial(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")

		assert.Equal(t, 1, len(partialResults.Queries), "Rego policy allows illegal input")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}

		opaEvaluator, err := NewOPAEvaluator(queryString, opaModule, input)
		assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PermissionQuery.Eval(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := opaEvaluator.PermissionQuery.Partial(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")

		assert.Equal(t, 0, len(partialResults.Queries), "Rego policy allows illegal input")
	})
}

func TestGetOPAModuleConfig(t *testing.T) {
	t.Run(`GetOPAModuleConfig fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetOPAModuleConfig(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetOPAModuleConfig returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), OPAModuleConfigKey{}, &OPAModuleConfig{})
		opaEval, err := GetOPAModuleConfig(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, opaEval != nil, "OPA Module config not found.")
	})
}
