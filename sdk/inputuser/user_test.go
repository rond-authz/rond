package inputuser

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/mocks"
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

		user, err := GetInputUser(context.Background(), log, nil, inputUser)
		require.NoError(t, err)
		require.Equal(t, core.InputUser{
			ID:     "userId",
			Groups: []string{"group1", "group2"},
		}, user)
	})

	t.Run("extract user with no id in headers does not perform queries", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}

		_, err := GetInputUser(context.Background(), log, mock, types.User{})
		require.NoError(t, err)
	})

	t.Run("extract user but retrieve bindings fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindingsError: fmt.Errorf("some error"),
		}
		user := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		_, err := GetInputUser(context.Background(), log, mock, user)
		require.Error(t, err, "Error while retrieving user bindings: some error")
	})

	t.Run("extract user bindings but retrieve roles by role id fails", func(t *testing.T) {
		mock := mocks.MongoClientMock{
			UserBindings: []types.Binding{
				{Roles: []string{"r1", "r2"}},
			},
			UserRolesError: fmt.Errorf("some error 2"),
		}
		user := types.User{
			Groups: []string{"group1", "group2"},
			ID:     "userId",
		}

		_, err := GetInputUser(context.Background(), log, mock, user)
		require.Error(t, err, "Error while retrieving user Roles: some error 2")
	})

	t.Run("extract user bindings and roles", func(t *testing.T) {
		mock := mocks.MongoClientMock{
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

		inputUser, err := GetInputUser(context.Background(), log, mock, user)

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

	// TODO: migrate those tests
	// t.Run("allow empty userproperties header", func(t *testing.T) {
	// 	user := types.User{
	// 		Groups:     []string{"group1", "group2"},
	// 		ID:         "userId",
	// 		Properties: "",
	// 	}

	// 	inputUser, err := GetInputUser(context.Background(), log, mock, user)
	// 	require.NoError(t, err)
	// 	require.Equal(t, types.User{
	// 		ID:         "userId",
	// 		Groups:     []string{"group1", "group2"},
	// 		Properties: map[string]interface{}{},
	// 	}, inputUser)
	// })

	// t.Run("fail on invalid userproperties header value", func(t *testing.T) {
	// 	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// 	req.Header.Set("userproperties", "1")

	// 	_, err := RetrieveUserBindingsAndRoles(log, req, userHeaders)
	// 	require.ErrorContains(t, err, "user properties header is not valid:")
	// })
}
