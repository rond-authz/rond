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

package mocks

import (
	"context"
)

type FindOneExpectation struct {
	Query          map[string]string
	CollectionName string
}

type MongoClientMock struct {
	FindOneError        error
	FindOneResult       interface{}
	FindManyError       error
	FindOneExpectation  func(collectionName string, query interface{})
	FindManyExpectation func(collectionName string, query interface{})
	FindManyResult      []interface{}
}

func (mongoClient MongoClientMock) Disconnect() error {
	return nil
}

func (mongoClient MongoClientMock) FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error) {
	if mongoClient.FindOneExpectation == nil {
		panic("FindOneExpectation is required")
	}
	mongoClient.FindOneExpectation(collectionName, query)
	if mongoClient.FindOneError != nil {
		return nil, mongoClient.FindOneError
	}

	return mongoClient.FindOneResult, nil
}

func (mongoClient MongoClientMock) FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error) {
	if mongoClient.FindManyExpectation == nil {
		panic("FindManyExpectation is required")
	}
	mongoClient.FindManyExpectation(collectionName, query)
	if mongoClient.FindManyError != nil {
		return nil, mongoClient.FindManyError
	}

	return mongoClient.FindManyResult, nil
}
