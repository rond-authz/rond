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
	"fmt"
	"testing"

	"github.com/rond-authz/rond/logger"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestCreateRegoInput(t *testing.T) {
	log := logger.NewNullLogger()

	t.Run("returns correctly", func(t *testing.T) {
		actual, err := CreateRegoQueryInput(log, Input{}, RegoInputOptions{})
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

			input.buildOptimizedResourcePermissionsMap(log, true)
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

			input.buildOptimizedResourcePermissionsMap(log, false)
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

			input.buildOptimizedResourcePermissionsMap(log, true)
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

			input.buildOptimizedResourcePermissionsMap(log, true)
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

	logger := logger.NewNullLogger()
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
