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

package mocks

import (
	"context"

	"github.com/rond-authz/rond/types"
)

// TODO: rename this, is not related to mongo it's the mock of the inputuser client
type MongoClientMock struct {
	UserBindingsError error
	UserRolesError    error
	UserRoles         []types.Role
	UserBindings      []types.Binding
}

func (mongoClient MongoClientMock) Disconnect() error {
	return nil
}

func (mongoClient MongoClientMock) RetrieveRoles(ctx context.Context) ([]types.Role, error) {
	return nil, nil
}

func (mongoClient MongoClientMock) RetrieveUserBindings(ctx context.Context, user types.User) ([]types.Binding, error) {
	if mongoClient.UserBindings != nil {
		return mongoClient.UserBindings, nil
	}
	return nil, mongoClient.UserBindingsError
}

func (mongoClient MongoClientMock) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	if mongoClient.UserRoles != nil {
		return mongoClient.UserRoles, nil
	}
	return nil, mongoClient.UserRolesError
}
