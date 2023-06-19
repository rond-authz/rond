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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/fake"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

var mockRondConfigWithQueryGen = openapi.RondConfig{
	RequestFlow: openapi.RequestFlow{
		PolicyName:    "allow",
		GenerateQuery: true,
		QueryOptions: openapi.QueryOptions{
			HeaderName: "rowfilterquery",
		},
	},
}

func TestDirectProxyHandler(t *testing.T) {
	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{PolicyName: "todo"},
					},
				},
			},
		},
	}

	oasWithFilter := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{
							PolicyName:    "allow",
							GenerateQuery: true,
							QueryOptions: openapi.QueryOptions{
								HeaderName: "rowfilterquery",
							},
						},
					},
				},
			},
		},
	}

	log, _ := test.NewNullLogger()
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

	t.Run("opens backend server and sends it request using proxy", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true

			require.Equal(t, "/api", r.URL.Path, "Mocked Backend: Unexpected path of request url")
			require.Equal(t, "mockQuery=iamquery", r.URL.RawQuery, "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)

		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		require.NoError(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("sends request with custom headers", func(t *testing.T) {
		invoked := false
		mockHeader := "CustomHeader"
		mockHeaderValue := "mocked value"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			require.Equal(t, mockHeaderValue, r.Header.Get(mockHeader), "Mocked Backend: Mocked Header not found")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set(mockHeader, mockHeaderValue)
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("sends request with body", func(t *testing.T) {
		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
	})

	t.Run("sends request with body after serialization in rego input", func(t *testing.T) {
		invoked := false
		mockBodySting := `{"hello":"world"}`
		OPAModuleConfig := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
				todo { input.request.body.hello == "world" }`,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		rondConfig := openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}
		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, rondConfig, oas)

		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://www.example.com:8080/api", body)
		r.Header.Set(utils.ContentTypeHeaderKey, "application/json")
		require.NoError(t, err, "Unexpected error")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
	})

	t.Run("sends filter query", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "value"
	input.request.method == "GET"
	employee := data.resources[_]
	employee.name == "name_test"
}

allow {
	input.request.method == "GET"

	employee := data.resources[_]
	employee.manager == "manager_test"
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary > 0
}
`

		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := `{"$or":[{"$and":[{"manager":{"$eq":"manager_test"}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
			require.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
	})

	t.Run("sends filter query with nested data", func(t *testing.T) {
		policy := `package policies
allow {
	employee := data.resources[_]
	employee.data.manager == "manager_test"
}
`

		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := `{"$or":[{"$and":[{"data.manager":{"$eq":"manager_test"}}]}]}`
			require.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
	})

	t.Run("sends empty filter query", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "value"
	input.request.method == "GET"
	employee := data.resources[_]
}

allow {
	input.request.method == "GET"

	employee := data.resources[_]
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
}
`

		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := ``
			require.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
	})

	// https://github.com/rond-authz/rond/issues/161
	t.Run("issue #161", func(t *testing.T) {

		t.Run("issue repro", func(t *testing.T) {
			policy := `package policies
allow {
	resource := data.resources[_]
	print(resource)
}
	`

			invoked := false
			mockBodySting := "I am a body"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				defer r.Body.Close()
				buf, err := io.ReadAll(r.Body)
				require.NoError(t, err, "Mocked backend: Unexpected error")
				require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
				filterQuery := r.Header.Get("rowfilterquery")
				expectedQuery := ``
				require.Equal(t, expectedQuery, filterQuery)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Mocked Backend Body Example"))
			}))
			defer server.Close()

			body := strings.NewReader(mockBodySting)

			OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

			evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				evaluator,
				OPAModuleConfig,
				nil,
			)

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
			require.NoError(t, err, "Unexpected error")
			r.Header.Set("miauserproperties", `{"name":"gianni"}`)
			r.Header.Set("examplekey", "value")
			r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			buf, err := io.ReadAll(w.Body)
			require.NoError(t, err, "Unexpected error to read body response")
			require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
		})

		t.Run("print statement support", func(t *testing.T) {
			policy := `package policies
allow {
	employee := data.resources[_]
	print("hi")
	employee.manager == "manager_test"
	print("hi")
}
	`

			invoked := false
			mockBodySting := "I am a body"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				defer r.Body.Close()
				buf, err := io.ReadAll(r.Body)
				require.NoError(t, err, "Mocked backend: Unexpected error")
				require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
				filterQuery := r.Header.Get("rowfilterquery")
				expectedQuery := `{"$or":[{"$and":[{"manager":{"$eq":"manager_test"}}]}]}`
				require.Equal(t, expectedQuery, filterQuery)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Mocked Backend Body Example"))
			}))
			defer server.Close()

			body := strings.NewReader(mockBodySting)

			OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

			evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				evaluator,
				OPAModuleConfig,
				nil,
			)

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
			require.NoError(t, err, "Unexpected error")
			r.Header.Set("miauserproperties", `{"name":"gianni"}`)
			r.Header.Set("examplekey", "value")
			r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			buf, err := io.ReadAll(w.Body)
			require.NoError(t, err, "Unexpected error to read body response")
			require.Equal(t, "Mocked Backend Body Example", string(buf), "Unexpected body response")
		})
	})

	t.Run("sends empty filter query with application-json as content-type", func(t *testing.T) {
		policy := `package policies
allow {
	false
	employee := data.resources[_]
	employee.name == "name_test"
}
`

		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fail()
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set(utils.ContentTypeHeaderKey, "application/json")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		require.Equal(t, utils.JSONContentTypeHeader, w.Result().Header.Get(utils.ContentTypeHeaderKey), "Unexpected content type.")
		buf, err := io.ReadAll(w.Body)
		require.NoError(t, err, "Unexpected error to read body response")
		require.Equal(t, "[]", string(buf), "Unexpected body response")
	})

	t.Run("sends empty filter query with text/plain as content-type", func(t *testing.T) {
		policy := `package policies
allow {
	false
	employee := data.resources[_]
	employee.name == "name_test"
}
`

		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, !invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("filter query return not allow", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "test"
	input.request.method == "DELETE"
	employee := data.resources[_]
	employee.name == "name_test"
}

allow {
	input.request.method == "GET111"

	employee := data.resources[_]
	employee.manager == "manager_test"
}

allow {
	input.request.method == "GETAAA"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary < 0
}
`

		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := io.ReadAll(r.Body)
			require.NoError(t, err, "Mocked backend: Unexpected error")
			require.Equal(t, mockBodySting, string(buf), "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := ``
			require.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		OPAModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			OPAModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(utils.ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, !invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
		require.Equal(t, utils.JSONContentTypeHeader, w.Result().Header.Get(utils.ContentTypeHeaderKey), "Unexpected content type.")
	})

	t.Run("data evaluation correctly added - logs and metrics", func(t *testing.T) {
		t.Run("no query generation", func(t *testing.T) {
			invoked := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true

				require.Equal(t, "/api", r.URL.Path, "Mocked Backend: Unexpected path of request url")
				require.Equal(t, "mockQuery=iamquery", r.URL.RawQuery, "Mocked Backend: Unexpected rawQuery of request url")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas)
			ctx := createContext(t,
				ctx,
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				evaluator,
				mockOPAModule,
				nil,
			)

			log, hook := test.NewNullLogger()
			log.Level = logrus.TraceLevel
			ctx = glogger.WithLogger(ctx, logrus.NewEntry(log))

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
			require.NoError(t, err, "Unexpected error")

			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")

			t.Run("logs", func(t *testing.T) {
				actualLog := findLogWithMessage(hook.AllEntries(), "policy evaluation completed")
				require.Len(t, actualLog, 1)
				require.NotEmpty(t, actualLog[0].Data["evaluationTimeMicroseconds"])
				delete(actualLog[0].Data, "evaluationTimeMicroseconds")
				require.Equal(t, logrus.Fields{
					"allowed":       true,
					"matchedPath":   "/matched/path",
					"method":        "GET",
					"partialEval":   false,
					"policyName":    "todo",
					"requestedPath": "/requested/path",
				}, actualLog[0].Data)
			})

			t.Run("metrics", func(t *testing.T) {
				m, err := metrics.GetFromContext(ctx)
				require.NoError(t, err)
				registry := prometheus.NewPedanticRegistry()
				m.MustRegister(registry)

				problem, err := testutil.CollectAndLint(registry, "test_rond_policy_evaluation_duration_milliseconds")
				require.NoError(t, err, problem)
				require.Equal(t, 1, testutil.CollectAndCount(registry, "test_rond_policy_evaluation_duration_milliseconds"), "register")
			})
		})

		t.Run("with query generation", func(t *testing.T) {
			invoked := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true

				require.Equal(t, "/api", r.URL.Path, "Mocked Backend: Unexpected path of request url")
				require.Equal(t, "mockQuery=iamquery", r.URL.RawQuery, "Mocked Backend: Unexpected rawQuery of request url")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			OPAModuleConfig := &core.OPAModuleConfig{
				Name: "mypolicy.rego",
				Content: `package policies
allow {
	input.request.method == "GET"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary < 0
}`,
			}

			evaluator := getEvaluator(t, ctx, OPAModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
			ctx := createContext(t,
				ctx,
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				evaluator,
				OPAModuleConfig,
				nil,
			)

			log, hook := test.NewNullLogger()
			log.Level = logrus.TraceLevel
			ctx = glogger.WithLogger(ctx, logrus.NewEntry(log))

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
			require.NoError(t, err, "Unexpected error")

			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")

			t.Run("logs", func(t *testing.T) {
				actualLog := findLogWithMessage(hook.AllEntries(), "policy evaluation completed")
				require.Len(t, actualLog, 1)
				require.NotEmpty(t, actualLog[0].Data["evaluationTimeMicroseconds"])
				delete(actualLog[0].Data, "evaluationTimeMicroseconds")
				require.Equal(t, logrus.Fields{
					"allowed":       true,
					"matchedPath":   "/matched/path",
					"method":        "GET",
					"partialEval":   true,
					"policyName":    "allow",
					"requestedPath": "/requested/path",
				}, actualLog[0].Data)
			})

			t.Run("metrics", func(t *testing.T) {
				m, err := metrics.GetFromContext(ctx)
				require.NoError(t, err)
				registry := prometheus.NewPedanticRegistry()
				m.MustRegister(registry)

				problem, err := testutil.CollectAndLint(registry, "test_rond_policy_evaluation_duration_milliseconds")
				require.NoError(t, err, problem)
				require.Equal(t, 1, testutil.CollectAndCount(registry, "test_rond_policy_evaluation_duration_milliseconds"), "register")
			})
		})
	})
}

func TestStandaloneMode(t *testing.T) {
	env := config.EnvironmentVariables{Standalone: true}
	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{PolicyName: "todo"},
					},
				},
			},
		},
	}

	oasWithFilter := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{
							PolicyName:    "allow",
							GenerateQuery: true,
							QueryOptions: openapi.QueryOptions{
								HeaderName: "rowfilterquery",
							},
						},
					},
				},
			},
		},
	}

	log, _ := test.NewNullLogger()
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

	t.Run("ok", func(t *testing.T) {
		evaluator := getEvaluator(t, ctx, mockOPAModule, nil, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			env,
			evaluator,
			mockOPAModule,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		require.NoError(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("sends filter query", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "value"
	input.request.method == "GET"
	employee := data.resources[_]
	employee.name == "name_test"
}

allow {
	input.request.method == "GET"

	employee := data.resources[_]
	employee.manager == "manager_test"
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary > 0
}
`

		mockBodySting := "I am a body"

		body := strings.NewReader(mockBodySting)

		opaModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
		evaluator := getEvaluator(t, ctx, opaModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			env,
			evaluator,
			opaModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		filterQuery := r.Header.Get("rowfilterquery")
		expectedQuery := `{"$or":[{"$and":[{"manager":{"$eq":"manager_test"}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
		require.Equal(t, expectedQuery, filterQuery)
	})

	t.Run("sends filter query with $in", func(t *testing.T) {
		t.Run("as array", func(t *testing.T) {

			policy := `package policies
import future.keywords.in

allow {
	input.request.method == "GET"

	employee := data.resources[_]
	["member_test"] in employee.membership
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary > 0
}
`

			mockBodySting := "I am a body"

			body := strings.NewReader(mockBodySting)

			opaModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
			evaluator := getEvaluator(t, ctx, opaModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
			ctx := createContext(t,
				context.Background(),
				env,
				evaluator,
				opaModuleConfig,
				nil,
			)

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
			require.NoError(t, err, "Unexpected error")
			r.Header.Set("miauserproperties", `{"name":"gianni"}`)
			r.Header.Set("examplekey", "value")
			r.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := `{"$or":[{"$and":[{"membership":{"$in":["member_test"]}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
			require.Equal(t, expectedQuery, filterQuery)
		})

		t.Run("as single item", func(t *testing.T) {

			policy := `package policies
import future.keywords.in

allow {
	input.request.method == "GET"
	groups := {"groupid":123}

	query := data.resources[_]
	groups.groupid in query.membership
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary > 0
}
`

			mockBodySting := "I am a body"

			body := strings.NewReader(mockBodySting)

			opaModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
			evaluator := getEvaluator(t, ctx, opaModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
			ctx := createContext(t,
				context.Background(),
				env,
				evaluator,
				opaModuleConfig,
				nil,
			)

			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
			require.NoError(t, err, "Unexpected error")
			r.Header.Set("miauserproperties", `{"name":"gianni"}`)
			r.Header.Set("examplekey", "value")
			r.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()

			rbacHandler(w, r)

			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := `{"$or":[{"$and":[{"membership":{"$in":[123]}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
			require.Equal(t, expectedQuery, filterQuery)
		})
	})

	t.Run("sends empty filter query", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "value"
	input.request.method == "GET"
	employee := data.resources[_]
}

allow {
	input.request.method == "GET"

	employee := data.resources[_]
}

allow {
	input.request.method == "GET"
	input.request.path == "/api"
}
`

		mockBodySting := "I am a body"

		body := strings.NewReader(mockBodySting)

		opaModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
		evaluator := getEvaluator(t, ctx, opaModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			env,
			evaluator,
			opaModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		filterQuery := r.Header.Get("rowfilterquery")
		expectedQuery := ``
		require.Equal(t, expectedQuery, filterQuery)
	})

	t.Run("filter query return not allow", func(t *testing.T) {
		policy := `package policies
allow {
	get_header("examplekey", input.headers) == "test"
	input.request.method == "DELETE"
	employee := data.resources[_]
	employee.name == "name_test"
}

allow {
	input.request.method == "GET111"

	employee := data.resources[_]
	employee.manager == "manager_test"
}

allow {
	input.request.method == "GETAAA"
	input.request.path == "/api"
	employee := data.resources[_]
	employee.salary < 0
}
`

		mockBodySting := "I am a body"
		body := strings.NewReader(mockBodySting)

		opaModuleConfig := &core.OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
		evaluator := getEvaluator(t, ctx, opaModuleConfig, nil, mockRondConfigWithQueryGen, oasWithFilter)
		ctx := createContext(t,
			context.Background(),
			env,
			evaluator,
			opaModuleConfig,
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		require.NoError(t, err, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
	})
}

func TestPolicyEvaluationAndUserPolicyRequirements(t *testing.T) {
	userPropertiesHeaderKey := "miauserproperties"
	mockedUserProperties := map[string]interface{}{
		"my":  "other",
		"key": []string{"is", "not"},
	}
	mockedUserPropertiesStringified, err := json.Marshal(mockedUserProperties)
	require.NoError(t, err)

	userGroupsHeaderKey := "miausergroups"
	mockedUserGroups := []string{"group1", "group2"}
	mockedUserGroupsHeaderValue := strings.Join(mockedUserGroups, ",")

	clientTypeHeaderKey := "Client-Type"
	mockedClientType := "fakeClient"

	userIdHeaderKey := "miauserid"
	require.NoError(t, err)

	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: fmt.Sprintf(`
		package policies
		todo {
			input.user.properties.my == "%s"
			count(input.user.groups) == 2
			input.clientType == "%s"
		}`, mockedUserProperties["my"], mockedClientType),
	}

	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{PolicyName: "todo"},
					},
				},
			},
		},
	}

	log, _ := test.NewNullLogger()
	ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

	// TODO: this tests verifies policy execution based on request header evaluation, it is
	// useful as a documentation because right now headers are provided as-is from the
	// http.Header type which transforms any header key in `Camel-Case`, meaning a policy
	// **must** express headers in this fashion. This may subject to change before v1 release.
	t.Run("TestPolicyEvaluation", func(t *testing.T) {
		t.Run("policy on request header works correctly", func(t *testing.T) {
			invoked := false
			mockHeader := "X-Backdoor"
			mockHeaderValue := "mocked value"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, mockHeaderValue, r.Header.Get(mockHeader), "Mocked Backend: Mocked Header not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			t.Run("without get_header built-in function", func(t *testing.T) {
				opaModule := &core.OPAModuleConfig{
					Name: "example.rego",
					Content: fmt.Sprintf(`package policies
					todo { count(input.request.headers["%s"]) != 0 }`, mockHeader),
				}

				rondConfig := openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}
				evaluator := getEvaluator(t, ctx, opaModule, nil, rondConfig, oas)
				ctx := createContext(t,
					context.Background(),
					config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
					evaluator,
					opaModule,
					nil,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					require.NoError(t, err, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					require.True(t, invoked, "Handler was not invoked.")
					require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					require.NoError(t, err, "Unexpected error")

					rbacHandler(w, r)
					require.True(t, !invoked, "The policy did not block the request as expected")
					require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
				})
			})

			t.Run("using get_header built-in function to access in case-insensitive mode", func(t *testing.T) {
				invoked = false
				opaModule := &core.OPAModuleConfig{
					Name: "example.rego",
					Content: `package policies
					todo { get_header("x-backdoor", input.request.headers) == "mocked value" }`,
				}

				evaluator := getEvaluator(t, ctx, opaModule, nil, mockXPermission, oas)
				ctx := createContext(t,
					context.Background(),
					config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
					evaluator,
					opaModule,
					nil,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					require.NoError(t, err, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					require.True(t, invoked, "Handler was not invoked.")
					require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					require.NoError(t, err, "Unexpected error")

					rbacHandler(w, r)
					require.True(t, !invoked, "The policy did not block the request as expected")
					require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
				})
			})
		})

		t.Run("policy on user infos works correctly", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, string(mockedUserPropertiesStringified), r.Header.Get(userPropertiesHeaderKey), "Mocked User properties not found")
				require.Equal(t, mockedUserGroupsHeaderValue, r.Header.Get(userGroupsHeaderKey), "Mocked User groups not found")
				require.Equal(t, mockedClientType, r.Header.Get(clientTypeHeaderKey), "Mocked client type not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
				todo {
					input.user.properties.my == "%s"
					count(input.user.groups) == 2
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}

			evaluator := getEvaluator(t, ctx, opaModule, nil, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:    serverURL.Host,
					UserPropertiesHeader: userPropertiesHeaderKey,
					UserGroupsHeader:     userGroupsHeaderKey,
					ClientTypeHeader:     clientTypeHeaderKey,
				},
				evaluator,
				opaModule,
				nil,
			)

			t.Run("request respects the policy", func(t *testing.T) {
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				require.NoError(t, err, "Unexpected error")

				r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
				r.Header.Set(userGroupsHeaderKey, mockedUserGroupsHeaderValue)
				r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

				rbacHandler(w, r)
				require.True(t, invoked, "Handler was not invoked.")
				require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			})

			t.Run("request does not have the required header", func(t *testing.T) {
				invoked = false
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				require.NoError(t, err, "Unexpected error")

				rbacHandler(w, r)
				require.True(t, !invoked, "The policy did not block the request as expected")
				require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
			})
		})

		t.Run("testing return value of the evaluation", func(t *testing.T) {
			invoked := false
			mockHeader := "X-Backdoor"
			mockHeaderValue := "mocked value"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, mockHeaderValue, r.Header.Get(mockHeader), "Mocked Backend: Mocked Header not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`package policies
				todo[msg]{
					count(input.request.headers["%s"]) != 0
					msg := {"ciao":"boh"}
					test
				}
				test[x]{
					true
					x:= ["x"]
				}
				`, mockHeader),
			}

			oas := &openapi.OpenAPISpec{
				Paths: openapi.OpenAPIPaths{
					"/api": openapi.PathVerbs{
						"get": openapi.VerbConfig{
							PermissionV2: &openapi.RondConfig{
								RequestFlow: openapi.RequestFlow{PolicyName: "todo"},
							},
						},
					},
				},
			}

			rondConfig := &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}
			evaluator := getEvaluator(t, ctx, opaModule, nil, *rondConfig, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				evaluator,
				opaModule,
				nil,
			)

			t.Run("request respects the policy", func(t *testing.T) {
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				require.NoError(t, err, "Unexpected error")

				r.Header.Set(mockHeader, mockHeaderValue)

				rbacHandler(w, r)
				require.True(t, invoked, "Handler was not invoked.")
				require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
			})
		})
	})

	t.Run("Test retrieve roles ids from bindings", func(t *testing.T) {
		bindings := []types.Binding{
			{
				BindingID:         "binding1",
				Subjects:          []string{"user1"},
				Roles:             []string{"role1", "role2"},
				Groups:            []string{"group1"},
				Permissions:       []string{"permission4"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding2",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group4"},
				Permissions:       []string{"permission7"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding3",
				Subjects:          []string{"user5"},
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group2"},
				Permissions:       []string{"permission10", "permission4"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				BindingID:         "binding4",
				Roles:             []string{"role3", "role4"},
				Groups:            []string{"group2"},
				Permissions:       []string{"permission11"},
				CRUDDocumentState: "PUBLIC",
			},

			{
				BindingID:         "binding5",
				Subjects:          []string{"user1"},
				Roles:             []string{"role3", "role4"},
				Permissions:       []string{"permission12"},
				CRUDDocumentState: "PUBLIC",
			},
		}
		rolesIds := mongoclient.RolesIDsFromBindings(bindings)
		expected := []string{"role1", "role2", "role3", "role4"}
		require.True(t, reflect.DeepEqual(rolesIds, expected), "Error while getting permissions")
	})

	t.Run("TestHandlerWithUserPermissionsRetrievalFromMongoDB", func(t *testing.T) {
		t.Run("return 500 if retrieveUserBindings goes bad", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			mongoclientMock := &mocks.MongoClientMock{UserBindingsError: errors.New("Something went wrong"), UserBindings: nil, UserRoles: nil, UserRolesError: errors.New("Something went wrong")}

			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, mockedUserGroupsHeaderValue)
			r.Header.Set(userIdHeaderKey, "miauserid")
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusInternalServerError, "")
			require.True(t, !invoked, "Handler was not invoked.")
			require.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Unexpected status code.")
		})

		t.Run("return 500 if some errors occurs while querying mongoDB", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			mongoclientMock := &mocks.MongoClientMock{UserBindingsError: errors.New("MongoDB Error"), UserRolesError: errors.New("MongoDB Error")}

			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(userIdHeaderKey, "miauserid")
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseFullErrorMessages(t, w, http.StatusInternalServerError, "user bindings retrieval failed", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
			require.True(t, !invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("return 403 if user bindings and roles retrieval is ok but user has not the required permission", func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Handler has been called")
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			userBindings := []types.Binding{
				{
					BindingID:         "binding1",
					Subjects:          []string{"user1"},
					Roles:             []string{"role1", "role2"},
					Groups:            []string{"group1"},
					Permissions:       []string{"permission4"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding2",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group4"},
					Permissions:       []string{"permission7"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding3",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group2"},
					Permissions:       []string{"permission10", "permission4"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			userRoles := []types.Role{
				{
					RoleID:            "role3",
					Permissions:       []string{"permission1", "permission2", "foobar"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					RoleID:            "role4",
					Permissions:       []string{"permission3", "permission5"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			// Missing mia user properties required
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")

			rbacHandler(w, r)
			testutils.AssertResponseFullErrorMessages(t, w, http.StatusForbidden, "RBAC policy evaluation failed", utils.NO_PERMISSIONS_ERROR_MESSAGE)
			require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("return 200", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, string(mockedUserPropertiesStringified), r.Header.Get(userPropertiesHeaderKey), "Mocked User properties not found")
				require.Equal(t, string(mockedUserGroupsHeaderValue), r.Header.Get(userGroupsHeaderKey), "Mocked User groups not found")
				require.Equal(t, mockedClientType, r.Header.Get(clientTypeHeaderKey), "Mocked client type not found")
				require.Equal(t, userIdHeaderKey, r.Header.Get(userIdHeaderKey), "Mocked user id not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			userBindings := []types.Binding{
				{
					BindingID:         "binding1",
					Subjects:          []string{"user1"},
					Roles:             []string{"role1", "role2"},
					Groups:            []string{"group1"},
					Permissions:       []string{"permission4"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding2",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group4"},
					Permissions:       []string{"permission7"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding3",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group2"},
					Permissions:       []string{"permission10", "permission4"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			userRoles := []types.Role{
				{
					RoleID:            "role3",
					Permissions:       []string{"permission1", "permission2", "foobar"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					RoleID:            "role4",
					Permissions:       []string{"permission3", "permission5"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			serverURL, _ := url.Parse(server.URL)
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("return 200 with policy on bindings and roles", func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
				todo {
					input.user.properties.my == "%s"
					count(input.user.groups) == 2
					count(input.user.roles) == 2
					count(input.user.bindings)== 3
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}

			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, string(mockedUserPropertiesStringified), r.Header.Get(userPropertiesHeaderKey), "Mocked User properties not found")
				require.Equal(t, string(mockedUserGroupsHeaderValue), r.Header.Get(userGroupsHeaderKey), "Mocked User groups not found")
				require.Equal(t, mockedClientType, r.Header.Get(clientTypeHeaderKey), "Mocked client type not found")
				require.Equal(t, userIdHeaderKey, r.Header.Get(userIdHeaderKey), "Mocked user id not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			userBindings := []types.Binding{
				{
					BindingID:         "binding1",
					Subjects:          []string{"user1"},
					Roles:             []string{"role1", "role2"},
					Groups:            []string{"group1"},
					Permissions:       []string{"permission4"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding2",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group4"},
					Permissions:       []string{"permission7"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					BindingID:         "binding3",
					Subjects:          []string{"miauserid"},
					Roles:             []string{"role3", "role4"},
					Groups:            []string{"group2"},
					Permissions:       []string{"permission10", "permission4"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			userRoles := []types.Role{
				{
					RoleID:            "role3",
					Permissions:       []string{"permission1", "permission2", "foobar"},
					CRUDDocumentState: "PUBLIC",
				},
				{
					RoleID:            "role4",
					Permissions:       []string{"permission3", "permission5"},
					CRUDDocumentState: "PUBLIC",
				},
			}

			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			serverURL, _ := url.Parse(server.URL)
			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("return 200 without user header", func(t *testing.T) {
			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
				todo {
					input.user.properties.my == "%s"
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			mongoclientMock := &mocks.MongoClientMock{UserBindings: nil}

			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			rbacHandler(w, r)
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})

		t.Run("return 200 with policy on pathParams", func(t *testing.T) {
			customerId, productId := "1234", "5678"

			opaModule := &core.OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
				todo {
					input.request.pathParams.customerId == "%s"
					input.request.pathParams.productId == "%s"
				}`, customerId, productId),
			}

			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				require.Equal(t, string(mockedUserPropertiesStringified), r.Header.Get(userPropertiesHeaderKey), "Mocked User properties not found")
				require.Equal(t, string(mockedUserGroupsHeaderValue), r.Header.Get(userGroupsHeaderKey), "Mocked User groups not found")
				require.Equal(t, mockedClientType, r.Header.Get(clientTypeHeaderKey), "Mocked client type not found")
				require.Equal(t, userIdHeaderKey, r.Header.Get(userIdHeaderKey), "Mocked user id not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			userBindings := []types.Binding{}

			userRoles := []types.Role{}
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			serverURL, _ := url.Parse(server.URL)
			evaluator := getEvaluator(t, ctx, opaModule, mongoclientMock, mockXPermission, oas)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				evaluator,
				opaModule,
				mongoclientMock,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			r = mux.SetURLVars(r, map[string]string{
				"customerId": customerId,
				"productId":  productId,
			})
			require.NoError(t, err, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			require.True(t, invoked, "Handler was not invoked.")
			require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
		})
	})
}

func TestPolicyWithMongoBuiltinIntegration(t *testing.T) {
	var mockOPAModule = &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `
package policies
todo {
project := find_one("projects", {"projectId": "1234"})
project.tenantId == "1234"
}`,
	}
	var mockXPermission = openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "todo"}}
	oas := &openapi.OpenAPISpec{
		Paths: openapi.OpenAPIPaths{
			"/api": openapi.PathVerbs{
				"get": openapi.VerbConfig{
					PermissionV2: &openapi.RondConfig{
						RequestFlow: openapi.RequestFlow{PolicyName: "todo"},
					},
				},
			},
		},
	}

	t.Run("invokes target service", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		mongoMock := &mocks.MongoClientMock{
			FindOneExpectation: func(collectionName string, query interface{}) {
				require.Equal(t, "projects", collectionName)
				require.Equal(t, map[string]interface{}{
					"projectId": "1234",
				}, query)
			},
			FindOneResult: map[string]interface{}{"tenantId": "1234"},
		}

		userBindings := []types.Binding{}

		userRoles := []types.Role{}
		log, _ := test.NewNullLogger()
		mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))
		serverURL, _ := url.Parse(server.URL)

		evaluator := getEvaluator(t, ctxForPartial, mockOPAModule, mongoMock, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			mongoclientMock,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		require.NoError(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, invoked, "Handler was not invoked.")
		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("blocks for mongo error", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		mongoMock := &mocks.MongoClientMock{
			FindOneExpectation: func(collectionName string, query interface{}) {
				require.Equal(t, "projects", collectionName)
				require.Equal(t, map[string]interface{}{
					"projectId": "1234",
				}, query)
			},
			FindOneError: fmt.Errorf("FAILED MONGO QUERY"),
		}

		log, _ := test.NewNullLogger()

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctxForPartial, mockOPAModule, mongoMock, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			mongoMock,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		require.NoError(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, !invoked, "Handler was invoked.")
		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
	})

	t.Run("blocks for mongo not found", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		mongoMock := &mocks.MongoClientMock{
			FindOneExpectation: func(collectionName string, query interface{}) {
				require.Equal(t, "projects", collectionName)
				require.Equal(t, map[string]interface{}{
					"projectId": "1234",
				}, query)
			},
			FindOneResult: nil, // not found corresponds to a nil interface.
		}

		log, _ := test.NewNullLogger()

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))

		serverURL, _ := url.Parse(server.URL)
		evaluator := getEvaluator(t, ctxForPartial, mockOPAModule, mongoMock, mockXPermission, oas)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			evaluator,
			mockOPAModule,
			mongoMock,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		require.NoError(t, err, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		require.True(t, !invoked, "Handler was invoked.")
		require.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Unexpected status code.")
	})
}

func BenchmarkEvaluateRequest(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")
	permission := &openapi.RondConfig{RequestFlow: openapi.RequestFlow{PolicyName: "allow_view_project"}}

	queryString := fmt.Sprintf("data.policies.%s", permission.RequestFlow.PolicyName)
	query := rego.New(
		rego.Query(queryString),
		rego.Module(moduleConfig.Name, moduleConfig.Content),
		rego.Unknowns(core.Unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
		custom_builtins.MongoFindOne,
		custom_builtins.MongoFindMany,
	)

	pr, err := query.PartialResult(context.Background())
	if err != nil {
		panic(err)
	}

	partialEvaluators := core.PartialResultsEvaluators{
		permission.RequestFlow.PolicyName: core.PartialEvaluator{PartialEvaluator: &pr},
	}

	sdk := fake.NewSDKEvaluator(
		partialEvaluators,
		*permission,
		nil,
	)

	envs := config.EnvironmentVariables{
		UserGroupsHeader: "miausergroups",
		UserIdHeader:     "miauserid",
	}

	nilLogger, _ := test.NewNullLogger()
	logger := logrus.NewEntry(nilLogger)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		originalRequest := httptest.NewRequest(http.MethodGet, "/projects/project123", nil)
		req := originalRequest.WithContext(
			glogger.WithLogger(
				metrics.WithValue(
					context.WithValue(
						openapi.WithRouterInfo(
							logger,
							context.WithValue(
								openapi.WithXPermission(
									core.WithOPAModuleConfig(originalRequest.Context(), moduleConfig),
									permission,
								),
								types.MongoClientContextKey{}, testmongoMock,
							),
							httptest.NewRequest(http.MethodGet, "/", nil),
						),
						config.EnvKey{}, envs,
					),
					metrics.SetupMetrics(""),
				),
				logger,
			),
		)
		req.Header.Set("miausergroups", "area_rocket")
		req.Header.Set("miauserid", "user1")
		req = mux.SetURLVars(req, map[string]string{
			"projectId": "project123",
		})
		recorder := httptest.NewRecorder()
		b.StartTimer()
		EvaluateRequest(req, envs, recorder, sdk)
		b.StopTimer()
		require.Equal(b, http.StatusOK, recorder.Code)
	}
}

var testmongoMock = &mocks.MongoClientMock{
	UserBindings: []types.Binding{
		{
			BindingID:   "binding1",
			Subjects:    []string{"user1"},
			Roles:       []string{"admin"},
			Groups:      []string{"area_rocket"},
			Permissions: []string{"permission4"},
			Resource: &types.Resource{
				ResourceType: "project",
				ResourceID:   "project123",
			},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group4"},
			Permissions:       []string{"permission7"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding3",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission10", "permission4"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding4",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission11"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "bindingForRowFiltering",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "9876"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "bindingForRowFilteringFromSubject",
			Subjects:          []string{"filter_test"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "12345"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding5",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permission12"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "notUsedByAnyone",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "notUsedByAnyone2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role6"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PRIVATE",
		},
	},
	UserRoles: []types.Role{
		{
			RoleID:            "admin",
			Permissions:       []string{"console.project.view", "permission2", "foobar"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			RoleID:            "role3",
			Permissions:       []string{"permission3", "permission5", "console.project.view"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			RoleID:            "role6",
			Permissions:       []string{"permission3", "permission5"},
			CRUDDocumentState: "PRIVATE",
		},
		{
			RoleID:            "notUsedByAnyone",
			Permissions:       []string{"permissionNotUsed1", "permissionNotUsed2"},
			CRUDDocumentState: "PUBLIC",
		},
	},
}

func findLogWithMessage(logs []*logrus.Entry, message string) []*logrus.Entry {
	logToReturn := []*logrus.Entry{}
	for _, log := range logs {
		if log.Message == message {
			logToReturn = append(logToReturn, log)
		}
	}
	return logToReturn
}
