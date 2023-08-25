package inputuser

import (
	"context"
	"fmt"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"
)

func rolesIDsFromBindings(bindings []types.Binding) []string {
	rolesIds := []string{}
	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if !utils.Contains(rolesIds, role) {
				rolesIds = append(rolesIds, role)
			}
		}
	}
	return rolesIds
}

func GetInputUser(ctx context.Context, logger logging.Logger, client Client, user types.User) (core.InputUser, error) {
	inputUser := core.InputUser{
		Groups:     user.Groups,
		ID:         user.ID,
		Properties: user.Properties,
	}

	if client != nil && user.ID != "" {
		var err error
		inputUser.Bindings, err = client.RetrieveUserBindings(ctx, user)
		if err != nil {
			logger.WithField("error", map[string]any{"message": err.Error()}).Error("something went wrong while retrieving user bindings")
			return core.InputUser{}, fmt.Errorf("error while retrieving user bindings: %s", err.Error())
		}

		userRolesIds := rolesIDsFromBindings(inputUser.Bindings)
		inputUser.Roles, err = client.RetrieveUserRolesByRolesID(ctx, userRolesIds)
		if err != nil {
			logger.WithField("error", map[string]any{"message": err.Error()}).Error("something went wrong while retrieving user roles")

			return core.InputUser{}, fmt.Errorf("error while retrieving user Roles: %s", err.Error())
		}
		logger.WithFields(map[string]any{
			"foundBindingsLength": len(inputUser.Bindings),
			"foundRolesLength":    len(inputUser.Roles),
		}).Trace("found bindings and roles")
	}
	return inputUser, nil
}
