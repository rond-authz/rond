// Copyright 2023 Mia srl
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

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestCreateRegoInput(t *testing.T) {
	logrusLogger, _ := test.NewNullLogger()
	logger := logrus.NewEntry(logrusLogger)

	t.Run("returns correctly", func(t *testing.T) {
		actual, err := CreateRegoQueryInput(logger, Input{}, RegoInputOptions{})
		require.NoError(t, err)
		require.Equal(t, "{\"request\":{\"method\":\"\",\"path\":\"\"},\"response\":{},\"user\":{}}", string(actual))
	})

	t.Run("buildOptimizedResourcePermissionsMap", func(t *testing.T) {
		user := InputUser{
			Roles: []types.Role{
				{
					RoleID:      "role1",
					Permissions: []string{"permission1", "permission2"},
				},
				{
					RoleID:      "role2",
					Permissions: []string{"permission3", "permission4"},
				},
			},
			Bindings: []types.Binding{
				{
					Resource: &types.Resource{
						ResourceType: "type1",
						ResourceID:   "resource1",
					},
					Roles:       []string{"role1"},
					Permissions: []string{"permissionNotInRole1"},
				},
				{
					Resource: &types.Resource{
						ResourceType: "type2",
						ResourceID:   "resource2",
					},
					Roles: []string{"role2"},
				},
				{
					Resource: &types.Resource{
						ResourceType: "type3",
						ResourceID:   "resource3",
					},
					Roles:       []string{"role1", "role2"},
					Permissions: []string{"permissionNotInRole2", "permissionNotInRole3"},
				},
			},
		}

		t.Run("insert map", func(t *testing.T) {
			input := Input{
				User: user,
			}

			input.buildOptimizedResourcePermissionsMap(logger, true)
			expected := PermissionsOnResourceMap{
				"permission1:type1:resource1":          true,
				"permission2:type1:resource1":          true,
				"permissionNotInRole1:type1:resource1": true,
				"permission3:type2:resource2":          true,
				"permission4:type2:resource2":          true,
				"permission1:type3:resource3":          true,
				"permission2:type3:resource3":          true,
				"permission3:type3:resource3":          true,
				"permission4:type3:resource3":          true,
				"permissionNotInRole2:type3:resource3": true,
				"permissionNotInRole3:type3:resource3": true,
			}
			require.Equal(t, expected, input.User.ResourcePermissionsMap)
		})

		t.Run("do nothing if enableResourcePermissionsMapOptimization is false", func(t *testing.T) {
			input := Input{
				User: user,
			}

			input.buildOptimizedResourcePermissionsMap(logger, false)
			require.Nil(t, input.User.ResourcePermissionsMap)
		})

		t.Run("support bindings without resources", func(t *testing.T) {
			input := Input{
				User: InputUser{
					Roles: []types.Role{
						{RoleID: "role1", Permissions: []string{"permission1", "permission2"}},
						{RoleID: "role2", Permissions: []string{"permission3", "permission4"}},
					},
					Bindings: []types.Binding{
						{
							Resource: &types.Resource{
								ResourceType: "type1",
								ResourceID:   "resource1",
							},
							Roles:       []string{"role1"},
							Permissions: []string{"permissionNotInRole1"},
						},
						{
							Roles: []string{"role2"},
						},
						{
							Resource: &types.Resource{
								ResourceType: "type3",
								ResourceID:   "resource3",
							},
							Roles:       []string{"role1", "role2"},
							Permissions: []string{"permissionNotInRole2", "permissionNotInRole3"},
						},
					},
				},
			}

			input.buildOptimizedResourcePermissionsMap(logger, true)
			expected := PermissionsOnResourceMap{
				"permission1:type1:resource1":          true,
				"permission2:type1:resource1":          true,
				"permissionNotInRole1:type1:resource1": true,
				"permission1:type3:resource3":          true,
				"permission2:type3:resource3":          true,
				"permission3:type3:resource3":          true,
				"permission4:type3:resource3":          true,
				"permissionNotInRole2:type3:resource3": true,
				"permissionNotInRole3:type3:resource3": true,
			}
			require.Equal(t, expected, input.User.ResourcePermissionsMap)
		})

		t.Run("ignores unknown roles received from bindings", func(t *testing.T) {
			input := Input{
				User: InputUser{
					Roles: []types.Role{
						{RoleID: "role2", Permissions: []string{"permission3", "permission4"}},
					},
					Bindings: []types.Binding{
						{
							Resource: &types.Resource{
								ResourceType: "type1",
								ResourceID:   "resource1",
							},
							Roles:       []string{"role1"},
							Permissions: []string{"permissionNotInRole1"},
						},
						{
							Resource: &types.Resource{
								ResourceType: "type2",
								ResourceID:   "resource2",
							},
							Roles: []string{"role2"},
						},
						{
							Resource: &types.Resource{
								ResourceType: "type3",
								ResourceID:   "resource3",
							},
							Roles:       []string{"role1", "role2"},
							Permissions: []string{"permissionNotInRole2", "permissionNotInRole3"},
						},
					},
				},
			}

			input.buildOptimizedResourcePermissionsMap(logger, true)
			expected := PermissionsOnResourceMap{
				"permission3:type2:resource2":          true,
				"permission3:type3:resource3":          true,
				"permission4:type2:resource2":          true,
				"permission4:type3:resource3":          true,
				"permissionNotInRole1:type1:resource1": true,
				"permissionNotInRole2:type3:resource3": true,
				"permissionNotInRole3:type3:resource3": true,
			}
			require.Equal(t, expected, input.User.ResourcePermissionsMap)
		})
	})
}

func BenchmarkBuildOptimizedResourcePermissionsMap(b *testing.B) {
	var roles []types.Role
	for i := 0; i < 20; i++ {
		role := types.Role{
			RoleID:      fmt.Sprintf("role%d", i),
			Permissions: []string{fmt.Sprintf("permission%d", i), fmt.Sprintf("permission%d", i+1)},
		}
		roles = append(roles, role)

	}
	var bindings []types.Binding
	for i := 0; i < 100; i++ {
		binding := types.Binding{
			Resource: &types.Resource{
				ResourceType: fmt.Sprintf("type%d", i),
				ResourceID:   fmt.Sprintf("resource%d", i),
			},
			Roles:       []string{fmt.Sprintf("role%d", i)},
			Permissions: []string{fmt.Sprintf("permissionRole%d", i)},
		}
		bindings = append(bindings, binding)

	}
	user := InputUser{
		Roles:    roles,
		Bindings: bindings,
	}

	logrusLogger, _ := test.NewNullLogger()
	logger := logrus.NewEntry(logrusLogger)
	input := Input{
		User: user,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StartTimer()
		input.buildOptimizedResourcePermissionsMap(logger, true)
		b.StopTimer()
	}
}

func TestInputFromRequest(t *testing.T) {
	user := types.User{}
	clientTypeHeaderKey := "clienttypeheader"
	pathParams := map[string]string{}

	t.Run("request body integration", func(t *testing.T) {
		expectedRequestBody := map[string]interface{}{
			"Key": float64(42),
		}
		reqBody := struct{ Key int }{
			Key: 42,
		}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.Nil(t, err, "Unexpected error")

		t.Run("ignored on method GET", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(reqBodyBytes))

			rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
			input, err := rondRequest.FromRequestInfo(user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})

		t.Run("ignore nil body on method POST", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")

			rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
			input, err := rondRequest.FromRequestInfo(user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})

		t.Run("added on accepted methods", func(t *testing.T) {
			acceptedMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

			for _, method := range acceptedMethods {
				req := httptest.NewRequest(method, "/", bytes.NewReader(reqBodyBytes))
				req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
				rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
				input, err := rondRequest.FromRequestInfo(user, nil)
				require.NoError(t, err, "Unexpected error")
				require.Equal(t, expectedRequestBody, input.Request.Body)
			}
		})

		t.Run("added with content-type specifying charset", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBodyBytes))
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json;charset=UTF-8")
			rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
			input, err := rondRequest.FromRequestInfo(user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, expectedRequestBody, input.Request.Body)
		})

		t.Run("reject on method POST but with invalid body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
			rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
			_, err := rondRequest.FromRequestInfo(user, nil)
			require.ErrorContains(t, err, "failed request body deserialization:")
		})

		t.Run("ignore body on method POST but with another content type", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set(utils.ContentTypeHeaderKey, "multipart/form-data")

			rondRequest := NewRondInput(req, clientTypeHeaderKey, pathParams)
			input, err := rondRequest.FromRequestInfo(user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})
	})
}
