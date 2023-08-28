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
