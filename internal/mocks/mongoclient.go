package mocks

import (
	"context"

	"github.com/rond-authz/rond/types"
)

type FindOneExpectation struct {
	Query          map[string]string
	CollectionName string
}

type MongoClientMock struct {
	FindOneError        error
	UserBindingsError   error
	UserRolesError      error
	FindOneResult       interface{}
	FindManyError       error
	FindOneExpectation  func(collectionName string, query interface{})
	FindManyExpectation func(collectionName string, query interface{})
	UserRoles           []types.Role
	UserBindings        []types.Binding
	FindManyResult      []interface{}
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

func (mongoClient *MongoClientMock) FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error) {
	mongoClient.FindManyExpectation(collectionName, query)
	if mongoClient.FindManyError != nil {
		return nil, mongoClient.FindManyError
	}

	return mongoClient.FindManyResult, nil
}
