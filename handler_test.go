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

	"rbac-service/internal/mocks"
	"rbac-service/internal/testutils"
	"rbac-service/internal/types"
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
					Content: fmt.Sprintf(`package policies
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
					Content: `package policies
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
				r.Header.Set(userGroupsHeaderKey, mockedUserGroupsHeaderValue)
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
		rolesIds := rolesIdsFromBindings(bindings)
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

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindingsError: errors.New("Something went wrong"), UserBindings: nil, UserRoles: nil, UserRolesError: errors.New("Something went wrong")},
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
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindingsError: errors.New("MongoDB Error"), UserRolesError: errors.New("MongoDB Error")},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(userIdHeaderKey, "miauserid")
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusInternalServerError, "Error while retrieving user bindings: MongoDB Error")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusInternalServerError, "Unexpected status code.")
		})

		t.Run("return 403 if user bindings and roles retrieval is ok but user has not the required permission", func(t *testing.T) {
			invoked := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			// Missing mia user properties required
			r.Header.Set(userGroupsHeaderKey, string(mockedUserGroupsHeaderValue))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			r.Header.Set(userIdHeaderKey, "miauserid")

			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusForbidden, "RBAC policy evaluation failed")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
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

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles},
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
			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
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
			queryString := "todo"

			opaEvaluator, err := NewOPAEvaluator(queryString, opaModule)
			assert.NilError(t, err, "Unexpected error during creation of opaEvaluator")

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

			serverURL, _ := url.Parse(server.URL)
			ctx := createContext(t,
				context.Background(),
				EnvironmentVariables{
					TargetServiceHost:      serverURL.Host,
					UserPropertiesHeader:   userPropertiesHeaderKey,
					UserGroupsHeader:       userGroupsHeaderKey,
					UserIdHeader:           userIdHeaderKey,
					ClientTypeHeader:       clientTypeHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindings: userBindings, UserRoles: userRoles},
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
			assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		})

		t.Run("return 403 without user header", func(t *testing.T) {
			invoked := false

			opaModule := &OPAModuleConfig{
				Name: "example.rego",
				Content: fmt.Sprintf(`
				package policies
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
					UserIdHeader:           userIdHeaderKey,
					MongoDBUrl:             "mongodb://test",
					RolesCollectionName:    "roles",
					BindingsCollectionName: "bindings",
				},
				opaEvaluator,
				&mocks.MongoClientMock{UserBindings: nil},
			)

			w := httptest.NewRecorder()
			r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
			assert.Equal(t, err, nil, "Unexpected error")

			r.Header.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
			r.Header.Set(clientTypeHeaderKey, string(mockedClientType))
			rbacHandler(w, r)
			testutils.AssertResponseError(t, w, http.StatusForbidden, "Error while retrieving user permissions: user is unknown")
			assert.Assert(t, !invoked, "Handler was not invoked.")
			assert.Equal(t, w.Code, http.StatusForbidden, "Unexpected status code.")
		})
	})
}
