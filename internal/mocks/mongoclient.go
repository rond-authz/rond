package mocks

import (
	"context"

	"rbac-service/internal/types"
)

type MongoClientMock struct {
	UserBindings      []types.Binding
	UserBindingsError error
	UserRoles         []types.Role
	UserRolesError    error
}

func (mongoClient *MongoClientMock) Disconnect() {
}

func (mongoClient *MongoClientMock) RetrieveRoles(ctx context.Context) ([]types.Role, error) {
	return nil, nil
}

func (mongoClient *MongoClientMock) RetrieveUserBindings(ctx context.Context, user *types.User) ([]types.Binding, error) {
	if mongoClient.UserBindings != nil {
		return mongoClient.UserBindings, nil
	}
	return nil, mongoClient.UserBindingsError
}

func (mongoClient *MongoClientMock) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	if mongoClient.UserRoles != nil {
		return mongoClient.UserRoles, nil
	}
	return nil, mongoClient.UserRolesError
}
