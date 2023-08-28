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

package fake

import (
	"context"

	"github.com/rond-authz/rond/types"
)

type InputUserClient struct {
	UserBindingsError error
	UserRolesError    error
	UserRoles         []types.Role
	UserBindings      []types.Binding
}

func (iUser InputUserClient) Disconnect() error {
	return nil
}

func (iUser InputUserClient) RetrieveUserBindings(ctx context.Context, user types.User) ([]types.Binding, error) {
	if iUser.UserBindings != nil {
		return iUser.UserBindings, nil
	}
	return nil, iUser.UserBindingsError
}

func (iUser InputUserClient) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	if iUser.UserRoles != nil {
		return iUser.UserRoles, nil
	}
	return nil, iUser.UserRolesError
}
