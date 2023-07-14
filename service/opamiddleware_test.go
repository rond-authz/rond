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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestOPAMiddleware(t *testing.T) {
	getSDK := func(t *testing.T, oas *openapi.OpenAPISpec, opaModule *core.OPAModuleConfig) sdk.OASEvaluatorFinder {
		t.Helper()

		logger, _ := test.NewNullLogger()
		sdk, err := sdk.NewFromOAS(context.Background(), opaModule, oas, &sdk.Options{
			Logger: logrus.NewEntry(logger),
		})
		require.NoError(t, err, "unexpected error")

		return sdk
	}
	routesNotToProxy := make([]string, 0)

	t.Run(`strict mode failure`, func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
todo { true }`,
		}
		var openAPISpec *openapi.OpenAPISpec
		openAPISpecContent, err := os.ReadFile("../mocks/simplifiedMock.json")
		require.NoError(t, err)
		err = json.Unmarshal(openAPISpecContent, &openAPISpec)
		require.NoError(t, err)
		sdk := getSDK(t, openAPISpec, opaModule)

		middleware := OPAMiddleware(opaModule, sdk, routesNotToProxy, "", nil)

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
			openAPISpec, err := openapi.LoadOASFile("../mocks/documentationPathMock.json")
			require.NoError(t, err)
			targetServiceOASPath := "/documentation/json"
			sdk := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, sdk, routesNotToProxy, targetServiceOASPath, nil)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`ok - path is missing on oas and request is equal to serviceTargetOASPath`, func(t *testing.T) {
			openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
			require.NoError(t, err)
			targetServiceOASPath := "/documentation/json"
			sdk := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, sdk, routesNotToProxy, targetServiceOASPath, nil)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/documentation/json", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`ok - path is NOT known on oas but is proxied anyway`, func(t *testing.T) {
			openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
			require.NoError(t, err)
			targetServiceOASPath := "/documentation/custom/json"
			sdk := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, sdk, routesNotToProxy, targetServiceOASPath, nil)
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
		openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
		require.NoError(t, err)

		t.Run(`rego package doesn't contain expected policy`, func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name:    "example.rego",
				Content: `package policies another { true }`,
			}
			rondSDK := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", nil)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual, err := sdk.GetEvaluator(r.Context())
				require.NoError(t, err, "Unexpected error")
				require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "todo"}}, actual.Config())
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/users/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run(`rego package contains expected permission`, func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name:    "example.rego",
				Content: `package policies todo { true }`,
			}
			rondSDK := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", nil)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual, err := sdk.GetEvaluator(r.Context())
				require.NoError(t, err)
				require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "todo"}}, actual.Config())
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
			rondSDK := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", nil)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual, err := sdk.GetEvaluator(r.Context())
				require.NoError(t, err)
				require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "very.very.composed.permission"}}, actual.Config())
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

			options := &OPAMiddlewareOptions{
				IsStandalone:         false,
				PathPrefixStandalone: "/eval",
			}
			rondSDK := getSDK(t, openAPISpec, opaModule)

			middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", options)
			builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual, err := sdk.GetEvaluator(r.Context())
				require.NoError(t, err)
				require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "very.very.composed.permission.with.eval"}}, actual.Config())
				w.WriteHeader(http.StatusOK)
			}))

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/composed/permission/", nil)
			builtHandler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})
	})

	t.Run("with route to not proxy", func(t *testing.T) {
		routesNotToProxy := []string{"/not/proxy"}
		middleware := OPAMiddleware(nil, nil, routesNotToProxy, "", nil)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := sdk.GetEvaluator(r.Context())
			require.EqualError(t, err, sdk.ErrGetEvaluator.Error())
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/not/proxy", nil)
		builtHandler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})
}

func TestOPAMiddlewareStandaloneIntegration(t *testing.T) {
	var routesNotToProxy = []string{}

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	options := &OPAMiddlewareOptions{
		IsStandalone:         true,
		PathPrefixStandalone: "/eval",
	}
	getSdk := func(t *testing.T, opaModule *core.OPAModuleConfig) sdk.OASEvaluatorFinder {
		t.Helper()

		log, _ := test.NewNullLogger()
		logger := logrus.NewEntry(log)
		sdk, err := sdk.NewFromOAS(context.Background(), opaModule, openAPISpec, &sdk.Options{
			Logger: logger,
		})
		require.NoError(t, err, "unexpected error")

		return sdk
	}

	t.Run("injects correct path removing prefix", func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
			very_very_composed_permission { true }`,
		}

		rondSDK := getSdk(t, opaModule)
		middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", options)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actual, err := sdk.GetEvaluator(r.Context())
			require.NoError(t, err)
			require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "very.very.composed.permission"}}, actual.Config())
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

		rondSDK := getSdk(t, opaModule)
		middleware := OPAMiddleware(opaModule, rondSDK, routesNotToProxy, "", options)
		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actual, err := sdk.GetEvaluator(r.Context())
			require.NoError(t, err)
			require.Equal(t, core.RondConfig{RequestFlow: core.RequestFlow{PolicyName: "very.very.composed.permission.with.eval"}}, actual.Config())
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.com/eval/eval/composed/permission/", nil)
		builtHandler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})
}

func getJSONResponseBody[T any](t *testing.T, w *httptest.ResponseRecorder) *T {
	t.Helper()

	responseBody, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)

	out := new(T)
	if err := json.Unmarshal(responseBody, out); err != nil {
		require.Error(t, err, "fails to unmarshal")
	}
	return out
}
