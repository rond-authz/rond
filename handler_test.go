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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"

	"testing"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"gotest.tools/v3/assert"
)

func TestDirectProxyHandler(t *testing.T) {
	oas := OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "todo",
					},
				},
			},
		},
	}

	oasWithFilter := OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "allow",
						ResourceFilter: ResourceFilter{
							RowFilter: RowFilterConfiguration{
								HeaderKey: "rowfilterquery",
								Enabled:   true,
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

			assert.Equal(t, r.URL.Path, "/api", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "mockQuery=iamquery", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		partialEvaluators, err := setupEvaluators(ctx, nil, &oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			ctx,
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with custom headers", func(t *testing.T) {
		invoked := false
		mockHeader := "CustomHeader"
		mockHeaderValue := "mocked value"

		partialEvaluators, err := setupEvaluators(ctx, nil, &oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.Header.Get(mockHeader), mockHeaderValue, "Mocked Backend: Mocked Header not found")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(mockHeader, mockHeaderValue)
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with body", func(t *testing.T) {
		invoked := false
		mockBodySting := "I am a body"

		partialEvaluators, err := setupEvaluators(ctx, nil, &oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			ctx,
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			mockXPermission,
			mockOPAModule,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
	})

	t.Run("sends request with body after serialization in rego input", func(t *testing.T) {
		invoked := false
		mockBodySting := `{"hello":"world"}`
		opaModuleConfig := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
		todo { input.request.body.hello == "world" }`,
		}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oas, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{AllowPermission: "todo"},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://www.example.com:8080/api", body)
		r.Header.Set(ContentTypeHeaderKey, "application/json")
		assert.Equal(t, err, nil, "Unexpected error")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
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
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := `{"$or":[{"$and":[{"manager":{"$eq":"manager_test"}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
			assert.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
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
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := ``
			assert.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
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

		opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(ContentTypeHeaderKey, "application/json")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		assert.Equal(t, w.Result().Header.Get(ContentTypeHeaderKey), JSONContentTypeHeader, "Unexpected content type.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "[]", "Unexpected body response")
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

		opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, !invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
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
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			filterQuery := r.Header.Get("rowfilterquery")
			expectedQuery := ``
			assert.Equal(t, expectedQuery, filterQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)

		opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, opaModuleConfig, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},
			opaModuleConfig,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set(ContentTypeHeaderKey, "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, !invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
		assert.Equal(t, w.Result().Header.Get(ContentTypeHeaderKey), JSONContentTypeHeader, "Unexpected content type.")
	})
}

func TestStandaloneMode(t *testing.T) {
	env := config.EnvironmentVariables{Standalone: true}
	oas := OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "todo",
					},
				},
			},
		},
	}

	oasWithFilter := OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "allow",
						ResourceFilter: ResourceFilter{
							RowFilter: RowFilterConfiguration{
								HeaderKey: "rowfilterquery",
								Enabled:   true,
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
		partialEvaluators, err := setupEvaluators(ctx, nil, &oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")
		ctx := createContext(t,
			context.Background(),
			env,
			nil,
			mockXPermission,
			mockOPAModule,
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
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

		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		ctx := createContext(t,
			context.Background(),
			env,
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},

			&OPAModuleConfig{Name: "mypolicy.rego", Content: policy},
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		filterQuery := r.Header.Get("rowfilterquery")
		expectedQuery := `{"$or":[{"$and":[{"manager":{"$eq":"manager_test"}}]},{"$and":[{"salary":{"$gt":0}}]}]}`
		assert.Equal(t, expectedQuery, filterQuery)
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
		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		ctx := createContext(t,
			context.Background(),
			env,
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},

			&OPAModuleConfig{Name: "mypolicy.rego", Content: policy},
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		filterQuery := r.Header.Get("rowfilterquery")
		expectedQuery := ``
		assert.Equal(t, expectedQuery, filterQuery)
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
		partialEvaluators, err := setupEvaluators(ctx, nil, &oasWithFilter, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		body := strings.NewReader(mockBodySting)

		ctx := createContext(t,
			context.Background(),
			env,
			nil,
			&XPermission{
				AllowPermission: "allow",
				ResourceFilter: ResourceFilter{
					RowFilter: RowFilterConfiguration{
						HeaderKey: "rowfilterquery",
						Enabled:   true,
					},
				},
			},

			&OPAModuleConfig{Name: "mypolicy.rego", Content: policy},
			partialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("miauserproperties", `{"name":"gianni"}`)
		r.Header.Set("examplekey", "value")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
	})
}

func TestPolicyEvaluationAndUserPolicyRequirements(t *testing.T) {
	userPropertiesHeaderKey := "miauserproperties"
	mockedUserProperties := map[string]interface{}{
		"my":  "other",
		"key": []string{"is", "not"},
	}
	mockedUserPropertiesStringified, err := json.Marshal(mockedUserProperties)
	assert.NilError(t, err)

	userGroupsHeaderKey := "miausergroups"
	mockedUserGroups := []string{"group1", "group2"}
	mockedUserGroupsHeaderValue := strings.Join(mockedUserGroups, ",")

	clientTypeHeaderKey := "Client-Type"
	mockedClientType := "fakeClient"

	userIdHeaderKey := "miauserid"
	assert.NilError(t, err)

	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: fmt.Sprintf(`
		package policies
		todo {
			input.user.properties.my == "%s"
			count(input.user.groups) == 2
			input.clientType == "%s"
		}`, mockedUserProperties["my"], mockedClientType),
	}

	oas := &OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "todo",
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
				assert.Equal(t, r.Header.Get(mockHeader), mockHeaderValue, "Mocked Backend: Mocked Header not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			t.Run("without get_header built-in function", func(t *testing.T) {
				opaModule := &OPAModuleConfig{
					Name: "example.rego",
					Content: fmt.Sprintf(`package policies
					todo { count(input.request.headers["%s"]) != 0 }`, mockHeader),
				}

				partialEvaluators, err := setupEvaluators(ctx, nil, oas, opaModule, envs)
				assert.Equal(t, err, nil, "Unexpected error")

				ctx := createContext(t,
					context.Background(),
					config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
					nil,
					&XPermission{AllowPermission: "todo"},
					opaModule,
					partialEvaluators,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					assert.Assert(t, invoked, "Handler was not invoked.")
					assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					rbacHandler(w, r)
					assert.Assert(t, !invoked, "The policy did not block the request as expected")
					assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
				})
			})

			t.Run("using get_header built-in function to access in case-insensitive mode", func(t *testing.T) {
				invoked = false
				opaModule := &OPAModuleConfig{
					Name: "example.rego",
					Content: `package policies
					todo { get_header("x-backdoor", input.request.headers) == "mocked value" }`,
				}

				partialEvaluators, err := setupEvaluators(ctx, nil, oas, opaModule, envs)
				assert.Equal(t, err, nil, "Unexpected error")

				ctx := createContext(t,
					context.Background(),
					config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
					nil,
					mockXPermission,
					opaModule,
					partialEvaluators,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					assert.Assert(t, invoked, "Handler was not invoked.")
					assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					rbacHandler(w, r)
					assert.Assert(t, !invoked, "The policy did not block the request as expected")
					assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
				})
			})
		})

		t.Run("policy on user infos works correctly", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), mockedUserGroupsHeaderValue, "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
				todo {
					input.user.properties.my == "%s"
					count(input.user.groups) == 2
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}
			partialEvaluators, err := setupEvaluators(ctx, nil, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:    serverURL.Host,
					UserPropertiesHeader: userPropertiesHeaderKey,
					UserGroupsHeader:     userGroupsHeaderKey,
					ClientTypeHeader:     clientTypeHeaderKey,
				},
				nil,
				mockXPermission,
				opaModule,
				partialEvaluators,
			)

			t.Run("request respects the policy", func(t *testing.T) {
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				assert.Equal(t, err, nil, "Unexpected error")

				r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
				r.Header.Set(userGroupsHeaderKey, mockedUserGroupsHeaderValue)
				r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

				rbacHandler(w, r)
				assert.Assert(t, invoked, "Handler was not invoked.")
				assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
			})

			t.Run("request does not have the required header", func(t *testing.T) {
				invoked = false
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				assert.Equal(t, err, nil, "Unexpected error")

				rbacHandler(w, r)
				assert.Assert(t, !invoked, "The policy did not block the request as expected")
				assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
			})
		})

		t.Run("testing return value of the evaluation", func(t *testing.T) {
			invoked := false
			mockHeader := "X-Backdoor"
			mockHeaderValue := "mocked value"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				assert.Equal(t, r.Header.Get(mockHeader), mockHeaderValue, "Mocked Backend: Mocked Header not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			opaModule := &OPAModuleConfig{
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

			oas := OpenAPISpec{
				Paths: OpenAPIPaths{
					"/api": PathVerbs{
						"get": VerbConfig{
							XPermission{
								AllowPermission: "todo",
							},
						},
					},
				},
			}

			partialEvaluators, err := setupEvaluators(ctx, nil, &oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
				nil,
				&XPermission{AllowPermission: "todo"},
				opaModule,
				partialEvaluators,
			)

			t.Run("request respects the policy", func(t *testing.T) {
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				assert.Equal(t, err, nil, "Unexpected error")

				r.Header.Set(mockHeader, mockHeaderValue)

				rbacHandler(w, r)
				assert.Assert(t, invoked, "Handler was not invoked.")
				assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
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
		assert.Assert(t, reflect.DeepEqual(rolesIds, expected),
			"Error while getting permissions")
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

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindingsError: errors.New("Something went wrong"), UserBindings: nil, UserRoles: nil, UserRolesError: errors.New("Something went wrong")}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

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
				mongoclientMock,
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, mockedUserGroupsHeaderValue)
			r.Header.Set(userIdHeaderKey, "miauserid")
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusInternalServerError, "")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Unexpected status code.")
		})

		t.Run("return 500 if some errors occurs while querying mongoDB", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindingsError: errors.New("MongoDB Error"), UserRolesError: errors.New("MongoDB Error")}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

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
				mongoclientMock,
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(userIdHeaderKey, "miauserid")
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseFullErrorMessages(t, w, http.StatusInternalServerError, "user bindings retrieval failed", GENERIC_BUSINESS_ERROR_MESSAGE)
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError, "Unexpected status code.")
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

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

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
				mongoclientMock,
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			// Missing mia user properties required
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")

			rbacHandler(w, r)
			testutils.AssertResponseFullErrorMessages(t, w, http.StatusForbidden, "RBAC policy evaluation failed", NO_PERMISSIONS_ERROR_MESSAGE)
			assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
		})

		t.Run("return 200", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), string(mockedUserGroupsHeaderValue), "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				assert.Equal(t, r.Header.Get(userIdHeaderKey), userIdHeaderKey, "Mocked user id not found")
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

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}
			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				// opaEvaluator,
				&mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles},
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			assert.Assert(t, invoked, "Handler was not invoked.")
			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run("return 200 with policy on bindings and roles", func(t *testing.T) {

			opaModule := &OPAModuleConfig{
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
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), string(mockedUserGroupsHeaderValue), "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				assert.Equal(t, r.Header.Get(userIdHeaderKey), userIdHeaderKey, "Mocked user id not found")
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

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				&mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles},
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			assert.Assert(t, invoked, "Handler was not invoked.")
			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run("return 200 without user header", func(t *testing.T) {

			opaModule := &OPAModuleConfig{
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

			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindings: nil}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

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
				mongoclientMock,
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			rbacHandler(w, r)
			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})

		t.Run("return 200 with policy on pathParams", func(t *testing.T) {

			customerId, productId := "1234", "5678"

			opaModule := &OPAModuleConfig{
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
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), string(mockedUserGroupsHeaderValue), "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				assert.Equal(t, r.Header.Get(userIdHeaderKey), userIdHeaderKey, "Mocked user id not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			userBindings := []types.Binding{}

			userRoles := []types.Role{}
			log, _ := test.NewNullLogger()
			mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

			ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoclientMock), logrus.NewEntry(log))

			mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, opaModule, envs)
			assert.Equal(t, err, nil, "Unexpected error")

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				config.EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				mongoclientMock,
				mockXPermission,
				opaModule,
				mockPartialEvaluators,
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			r = mux.SetURLVars(r, map[string]string{
				"customerId": customerId,
				"productId":  productId,
			})
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			assert.Assert(t, invoked, "Handler was not invoked.")
			assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
		})
	})
}

func TestPolicyWithMongoBuiltinIntegration(t *testing.T) {
	var mockOPAModule = &OPAModuleConfig{
		Name: "example.rego",
		Content: `
package policies
todo {
project := find_one("projects", {"projectId": "1234"})
project.tenantId == "1234"
}`,
	}
	var mockXPermission = &XPermission{AllowPermission: "todo"}
	oas := &OpenAPISpec{
		Paths: OpenAPIPaths{
			"/api": PathVerbs{
				"get": VerbConfig{
					XPermission{
						AllowPermission: "todo",
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
				assert.Equal(t, collectionName, "projects")
				assert.DeepEqual(t, query, map[string]interface{}{
					"projectId": "1234",
				})
			},
			FindOneResult: map[string]interface{}{"tenantId": "1234"},
		}

		userBindings := []types.Binding{}

		userRoles := []types.Role{}
		log, _ := test.NewNullLogger()
		mongoclientMock := &mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles}

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))

		mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoclientMock, oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			mongoMock,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusOK, "Unexpected status code.")
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
				assert.Equal(t, collectionName, "projects")
				assert.DeepEqual(t, query, map[string]interface{}{
					"projectId": "1234",
				})
			},
			FindOneError: fmt.Errorf("FAILED MONGO QUERY"),
		}

		log, _ := test.NewNullLogger()

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))

		mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoMock, oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			mongoMock,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, !invoked, "Handler was invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
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
				assert.Equal(t, collectionName, "projects")
				assert.DeepEqual(t, query, map[string]interface{}{
					"projectId": "1234",
				})
			},
			FindOneResult: nil, // not found corresponds to a nil interface.
		}

		log, _ := test.NewNullLogger()

		ctxForPartial := glogger.WithLogger(mongoclient.WithMongoClient(context.Background(), mongoMock), logrus.NewEntry(log))

		mockPartialEvaluators, err := setupEvaluators(ctxForPartial, mongoMock, oas, mockOPAModule, envs)
		assert.Equal(t, err, nil, "Unexpected error")

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			config.EnvironmentVariables{TargetServiceHost: serverURL.Host},
			mongoMock,
			mockXPermission,
			mockOPAModule,
			mockPartialEvaluators,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, !invoked, "Handler was invoked.")
		assert.Equal(t, w.Result().StatusCode, http.StatusForbidden, "Unexpected status code.")
	})
}

func TestCreateQueryEvaluator(t *testing.T) {
	policy := `package policies
allow {
	true
}
column_policy{
	false
}
`
	permission := XPermission{
		AllowPermission: "allow",
		ResponseFilter: ResponseFilterConfiguration{
			Policy: "column_policy",
		},
	}

	ctx := createContext(t,
		context.Background(),
		config.EnvironmentVariables{TargetServiceHost: "test"},
		nil,
		&XPermission{
			AllowPermission: "allow",
			ResponseFilter: ResponseFilterConfiguration{
				Policy: "column_policy",
			},
		},

		&OPAModuleConfig{Name: "mypolicy.rego", Content: policy},
		nil,
	)

	r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
	assert.Equal(t, err, nil, "Unexpected error")
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	input := Input{Request: InputRequest{}, Response: InputResponse{}}
	inputBytes, _ := json.Marshal(input)

	t.Run("create  evaluator with allowPolicy", func(t *testing.T) {
		evaluator, err := createQueryEvaluator(context.Background(), logger, r, envs, permission.AllowPermission, inputBytes, nil)
		assert.Assert(t, evaluator != nil)
		assert.Equal(t, err, nil, "Unexpected status code.")
	})

	t.Run("create  evaluator with policy for column filtering", func(t *testing.T) {
		evaluator, err := createQueryEvaluator(context.Background(), logger, r, envs, permission.ResponseFilter.Policy, inputBytes, nil)
		assert.Assert(t, evaluator != nil)
		assert.Equal(t, err, nil, "Unexpected status code.")
	})
}

func BenchmarkEvaluateRequest(b *testing.B) {
	moduleConfig, err := loadRegoModule("./mocks/bench-policies")
	assert.NilError(b, err, "Unexpected error")
	permission := &XPermission{AllowPermission: "allow_view_project"}

	queryString := fmt.Sprintf("data.policies.%s", permission.AllowPermission)
	query := rego.New(
		rego.Query(queryString),
		rego.Module(moduleConfig.Name, moduleConfig.Content),
		rego.Unknowns(unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
		custom_builtins.MongoFindOne,
		custom_builtins.MongoFindMany,
	)

	pr, err := query.PartialResult(context.Background())
	if err != nil {
		panic(err)
	}

	partialEvaluators := PartialResultsEvaluators{
		permission.AllowPermission: PartialEvaluator{PartialEvaluator: &pr},
	}

	envs := config.EnvironmentVariables{
		UserGroupsHeader: "miausergroups",
		UserIdHeader:     "miauserid",
	}
	nilLogger, _ := test.NewNullLogger()

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		originalRequest := httptest.NewRequest(http.MethodGet, "/projects/project123", nil)
		req := originalRequest.WithContext(
			glogger.WithLogger(
				context.WithValue(
					context.WithValue(
						WithXPermission(
							WithOPAModuleConfig(originalRequest.Context(), moduleConfig),
							permission,
						),
						types.MongoClientContextKey{}, testmongoMock,
					),
					config.EnvKey{}, envs,
				),
				logrus.NewEntry(nilLogger),
			),
		)
		req.Header.Set("miausergroups", "area_rocket")
		req.Header.Set("miauserid", "user1")
		req = mux.SetURLVars(req, map[string]string{
			"projectId": "project123",
		})
		recorder := httptest.NewRecorder()
		b.StartTimer()
		EvaluateRequest(req, envs, recorder, partialEvaluators, permission)
		b.StopTimer()
		assert.Equal(b, recorder.Code, http.StatusOK)
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
