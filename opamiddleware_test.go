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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/types"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

var envs = config.EnvironmentVariables{}

var partialEvaluators = PartialResultsEvaluators{}

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
		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)

		t.Run(`missing oas paths`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/not-existing-path", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusNotFound, "Unexpected status code.")
			assert.DeepEqual(t, getJSONResponseBody[types.RequestError](t, w), &types.RequestError{
				Message:    "The request doesn't match any known API",
				Error:      "not found oas definition: GET /not-existing-path",
				StatusCode: http.StatusNotFound,
			})
			assert.Equal(t, w.Result().Header.Get(ContentTypeHeaderKey), JSONContentTypeHeader, "Unexpected content type.")
		})

		t.Run(`missing method`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodDelete, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusNotFound, "Unexpected status code.")
			assert.DeepEqual(t, getJSONResponseBody[types.RequestError](t, w), &types.RequestError{
				Message:    "The request doesn't match any known API",
				Error:      "not found oas definition: DELETE /users/",
				StatusCode: http.StatusNotFound,
			})
			assert.Equal(t, w.Result().Header.Get(ContentTypeHeaderKey), JSONContentTypeHeader, "Unexpected content type.")
		})

		t.Run(`missing permission`, func(t *testing.T) {
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com/no-permission", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
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

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`ok - path is missing on oas and request is equal to serviceTargetOASPath`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/simplifiedMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
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

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`ok - path is NOT known on oas but is proxied anyway`, func(t *testing.T) {
			var openAPISpec *OpenAPISpec
			openAPISpecContent, err := ioutil.ReadFile("./mocks/simplifiedMock.json")
			assert.NilError(t, err)
			_ = json.Unmarshal(openAPISpecContent, &openAPISpec)
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

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
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

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, permission, &XPermission{AllowPermission: "todo"})
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`rego package contains expected permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
foobar { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, permission, &XPermission{AllowPermission: "todo"})
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run(`rego package contains composed permission`, func(t *testing.T) {
			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: `package policies
very_very_composed_permission { true }`,
			}

			middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &XPermission{AllowPermission: "very.very.composed.permission"}, permission)
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run("injects correct permission", func(t *testing.T) {
			opaModule := &OPAModuleConfig{
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
				permission, err := GetXPermission(r.Context())
				require.True(t, err == nil, "Unexpected error")
				require.Equal(t, &XPermission{AllowPermission: "very.very.composed.permission.with.eval"}, permission)
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})
	})
}

func TestOPAMiddlewareStandaloneIntegration(t *testing.T) {
	var openAPISpec *OpenAPISpec
	openAPISpecContent, _ := ioutil.ReadFile("./mocks/simplifiedMock.json")
	_ = json.Unmarshal(openAPISpecContent, &openAPISpec)

	envs := config.EnvironmentVariables{
		Standalone:           true,
		PathPrefixStandalone: "/eval", // default value
	}

	t.Run("injects correct path removing prefix", func(t *testing.T) {
		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
			very_very_composed_permission { true }`,
		}

		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission, err := GetXPermission(r.Context())
			require.True(t, err == nil, "Unexpected error")
			require.Equal(t, &XPermission{AllowPermission: "very.very.composed.permission"}, permission)
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/composed/permission/", nil)
		builtHandler.ServeHTTP(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
	})

	t.Run("injects correct path removing only one prefix", func(t *testing.T) {
		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
very_very_composed_permission_with_eval { true }`,
		}

		middleware := OPAMiddleware(opaModule, openAPISpec, &envs, partialEvaluators)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission, err := GetXPermission(r.Context())
			require.True(t, err == nil, "Unexpected error")
			require.Equal(t, &XPermission{AllowPermission: "very.very.composed.permission.with.eval"}, permission)
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/eval/composed/permission/", nil)
		builtHandler.ServeHTTP(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
	})
}

func TestGetHeaderFunction(t *testing.T) {
	headerKeyMocked := "exampleKey"
	headerValueMocked := "value"
	env := config.EnvironmentVariables{}

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
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, env)
		assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, results.Allowed(), "The input is not allowed by rego")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")

		assert.Equal(t, 1, len(partialResults.Queries), "Rego policy allows illegal input")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, env)
		assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		assert.NilError(t, err, "Unexpected error during rego validation")
		assert.Assert(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
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

func getResponseBody(t *testing.T, w *httptest.ResponseRecorder) []byte {
	t.Helper()

	responseBody, err := ioutil.ReadAll(w.Result().Body)
	require.NoError(t, err)

	return responseBody
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
