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
	"strings"

	"rbac-service/internal/mocks"
	"rbac-service/internal/testutils"
	"testing"

	"gotest.tools/v3/assert"
)

func TestDirectProxyHandler(t *testing.T) {
	t.Run("opens backend server and sends it request using proxy", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true

			assert.Equal(t, r.URL.Path, "/api", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "mockQuery=iamquery", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with custom headers", func(t *testing.T) {
		invoked := false
		mockHeader := "CustomHeader"
		mockHeaderValue := "mocked value"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.Header.Get(mockHeader), mockHeaderValue, "Mocked Backend: Mocked Header not found")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(mockHeader, mockHeaderValue)
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with body", func(t *testing.T) {
		invoked := false
		mockBodySting := "I am a body"

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
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
			nil,
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
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
	mockedUserGroupsStringified, err := json.Marshal(mockedUserGroups)
	assert.NilError(t, err)

	clientTypeHeaderKey := "Client-Type"
	mockedClientType := "fakeClient"

	userIdHeaderKey := "miauserid"
	assert.NilError(t, err)

	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: fmt.Sprintf(`
		package example
		todo {
			input.user.properties.my == "%s"
			count(input.user.groups) == 2
			input.clientType == "%s"
		}`, mockedUserProperties["my"], mockedClientType),
	}
	queryString := "todo"

	opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
	assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

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
					Content: fmt.Sprintf(`package example
					todo { count(input.request.headers["%s"]) != 0 }`, mockHeader),
				}

				opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
				assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

				ctx := createContext(t,
					context.Background(),
					EnvironmentVariables{TargetServiceHost: serverURL.Host},
					opaEvaluator,
					nil,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					assert.Assert(t, invoked, "Handler was not invoked.")
					assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					rbacHandler(w, r)
					assert.Assert(t, !invoked, "The policy did not block the request as expected")
					assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
				})
			})

			t.Run("using get_header built-in function to access in case-insensitive mode", func(t *testing.T) {
				invoked = false
				opaModule := &OPAModuleConfig{
					Name: "example.rego",
					Content: `package example
					todo { get_header("x-backdoor", input.request.headers) == "mocked value" }`,
				}

				opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
				assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

				ctx := createContext(t,
					context.Background(),
					EnvironmentVariables{TargetServiceHost: serverURL.Host},
					opaEvaluator,
					nil,
				)

				t.Run("request respects the policy", func(t *testing.T) {
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					r.Header.Set(mockHeader, mockHeaderValue)

					rbacHandler(w, r)
					assert.Assert(t, invoked, "Handler was not invoked.")
					assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
				})

				t.Run("request does not have the required header", func(t *testing.T) {
					invoked = false
					w := httptest.NewRecorder()
					r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
					assert.Equal(t, err, nil, "Unexpected error")

					rbacHandler(w, r)
					assert.Assert(t, !invoked, "The policy did not block the request as expected")
					assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
				})
			})
		})

		t.Run("policy on user infos works correctly", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), string(mockedUserGroupsStringified), "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package example
				todo {
					input.user.properties.my == "%s"
					count(input.user.groups) == 2
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}
			queryString := "todo"

			opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
			assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:    serverURL.Host,
					UserPropertiesHeader: userPropertiesHeaderKey,
					UserGroupsHeader:     userGroupsHeaderKey,
					ClientTypeHeader:     clientTypeHeaderKey,
				},
				opaEvaluator,
				nil,
			)

			t.Run("request respects the policy", func(t *testing.T) {
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				assert.Equal(t, err, nil, "Unexpected error")

				r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
				r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsStringified))
				r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

				rbacHandler(w, r)
				assert.Assert(t, invoked, "Handler was not invoked.")
				assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
			})

			t.Run("request does not have the required header", func(t *testing.T) {
				invoked = false
				w := httptest.NewRecorder()
				r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
				assert.Equal(t, err, nil, "Unexpected error")

				rbacHandler(w, r)
				assert.Assert(t, !invoked, "The policy did not block the request as expected")
				assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
			})
		})
	})

	t.Run("TestUnmarshalHeader", func(t *testing.T) {

		t.Run("header not exists", func(t *testing.T) {
			headers := http.Header{}
			var userProperties map[string]interface{}

			ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)

			assert.Assert(t, !ok, "Unmarshal not existing header")
			assert.NilError(t, err, "Unexpected error if doesn't exist header")
		})

		t.Run("header exists but the unmarshalling fails", func(t *testing.T) {
			headers := http.Header{}
			headers.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			var userProperties string

			ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)

			assert.Assert(t, !ok, "Unexpected success during unmarshalling")
			assert.ErrorType(t, err, &json.UnmarshalTypeError{}, "Unexpected error on unmarshalling")
		})

		t.Run("header exists and unmarshalling finishes correctly", func(t *testing.T) {
			headers := http.Header{}
			headers.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			var userProperties map[string]interface{}

			ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)

			assert.Assert(t, ok, "Unexpected failure")
			assert.NilError(t, err, "Unexpected error")
		})
	})

	t.Run("TestHandlerWithUserPermissionsRetrievalFromMongoDB", func(t *testing.T) {
		t.Run("return 500 if findUserPermission goes bad", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserPermissionsError: errors.New("Something went wrong")},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusInternalServerError, "Error while retrieving user permissions: Something went wrong")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusInternalServerError, "Unexpected status code.")
		})

		t.Run("return 500 if some errors occurs while querying mongoDB", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserPermissionsError: errors.New("MongoDB Error")},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusInternalServerError, "Error while retrieving user permissions: MongoDB Error")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusInternalServerError, "Unexpected status code.")
		})

		t.Run("return 403 if user bindings retrieval is ok but user has not the required permission", func(t *testing.T) {
			invoked := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fail()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserPermissions: []string{"permission1"}},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusForbidden, "Error while retrieving user permissions: user is not allowed")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})

		t.Run("return 200", func(t *testing.T) {
			invoked := false

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				assert.Equal(t, r.Header.Get(userPropertiesHeaderKey), string(mockedUserPropertiesStringified), "Mocked User properties not found")
				assert.Equal(t, r.Header.Get(userGroupsHeaderKey), string(mockedUserGroupsStringified), "Mocked User groups not found")
				assert.Equal(t, r.Header.Get(clientTypeHeaderKey), mockedClientType, "Mocked client type not found")
				assert.Equal(t, r.Header.Get(userIdHeaderKey), userIdHeaderKey, "Mocked user id not found")
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserPermissions: []string{"todo"}},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")
			rbacHandler(w, r)
			assert.Assert(t, invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run("return 403 without user headers", func(t *testing.T) {
			invoked := false

			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package example
				todo {
					input.user.properties.my == "%s"
					input.clientType == "%s"
				}`, mockedUserProperties["my"], mockedClientType),
			}
			queryString := "todo"

			opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
			assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				invoked = true
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserPermissions: []string{}},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusForbidden, "Error while retrieving user permissions: user is not allowed")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})
	})
}
