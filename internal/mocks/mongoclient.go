package mocks

import (
	"context"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
)

type FindOneExpectation struct {
	CollectionName string
	Query          map[string]string
}

type MongoClientMock struct {
	UserBindings      []types.Binding
	UserBindingsError error
	UserRoles         []types.Role
	UserRolesError    error

	FindOneExpectation func(collectionName string, query interface{})
	FindOneResult      interface{}
	FindOneError       error
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

func (mongoClient *MongoClientMock) FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error) {
	mongoClient.FindOneExpectation(collectionName, query)
	if mongoClient.FindOneError != nil {
		return nil, mongoClient.FindOneError
	}

	return mongoClient.FindOneResult, nil
}
