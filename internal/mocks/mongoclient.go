package mocks

import (
	"context"

	"rbac-service/internal/types"
)

type MongoClientMock struct {
	UserPermissions      []string
	UserPermissionsError error
}

func (mongoClient *MongoClientMock) Disconnect() {
}

func (mongoClient *MongoClientMock) FindUserPermissions(ctx context.Context, user *types.User) ([]string, error) {
	if mongoClient.UserPermissions != nil {
		return mongoClient.UserPermissions, nil
	}
	return nil, mongoClient.UserPermissionsError
}
