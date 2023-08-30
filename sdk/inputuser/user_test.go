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

package inputuser

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/fake"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestRolesIDSFromBindings(t *testing.T) {
	t.Run("retrieve roles ids #1", func(t *testing.T) {
		result := rolesIDsFromBindings([]types.Binding{
			{Roles: []string{"a", "b"}},
			{Roles: []string{"a", "b"}},
			{Roles: []string{"c", "d"}},
			{Roles: []string{"e"}},
		})

		require.Equal(t, []string{"a", "b", "c", "d", "e"}, result)
	})

	t.Run("retrieve roles ids #2", func(t *testing.T) {
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
		rolesIds := rolesIDsFromBindings(bindings)
		expected := []string{"role1", "role2", "role3", "role4"}
		require.True(t, reflect.DeepEqual(rolesIds, expected), "Error while getting permissions")
	})
}

func TestRetrieveUserBindingsAndRoles(t *testing.T) {
	log := logging.NewNoOpLogger()

	t.Run("extract user from request without querying MongoDB if client not passed", func(t *testing.T) {
		inputUser := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		user, err := Get(context.Background(), log, nil, inputUser)
		require.NoError(t, err)
		require.Equal(t, core.InputUser{
			ID:     "userId",
			Groups: []string{"group1", "group2"},
		}, user)
	})

	t.Run("extract user with no id in headers does not perform queries", func(t *testing.T) {
		mock := fake.InputUserClient{
			UserBindingsError: fmt.Errorf("some error"),
		}

		_, err := Get(context.Background(), log, mock, types.User{})
		require.NoError(t, err)
	})

	t.Run("extract user but retrieve bindings fails", func(t *testing.T) {
		mock := fake.InputUserClient{
			UserBindingsError: fmt.Errorf("some error"),
		}
		user := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		_, err := Get(context.Background(), log, mock, user)
		require.Error(t, err, "Error while retrieving user bindings: some error")
	})

	t.Run("extract user bindings but retrieve roles by role id fails", func(t *testing.T) {
		mock := fake.InputUserClient{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
			},
			UserRolesError: fmt.Errorf("some error 2"),
		}
		user := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		_, err := Get(context.Background(), log, mock, user)
		require.Error(t, err, "Error while retrieving user Roles: some error 2")
	})

	t.Run("extract user bindings and roles", func(t *testing.T) {
		mock := fake.InputUserClient{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
				{Roles: []string{"r3"}},
			},
			UserRoles: []types.Role{
				{RoleID: "r1", Permissions: []string{"p1", "p2"}},
				{RoleID: "r2", Permissions: []string{"p3", "p4"}},
				{RoleID: "r3", Permissions: []string{"p5"}},
			},
		}
		user := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		inputUser, err := Get(context.Background(), log, mock, user)

		require.NoError(t, err)
		require.Equal(t, core.InputUser{
			ID:     "userId",
			Groups: []string{"group1", "group2"},
			Bindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
				{Roles: []string{"r3"}},
			},
			Roles: []types.Role{
				{RoleID: "r1", Permissions: []string{"p1", "p2"}},
				{RoleID: "r2", Permissions: []string{"p3", "p4"}},
				{RoleID: "r3", Permissions: []string{"p5"}},
			},
		}, inputUser)
	})
}
