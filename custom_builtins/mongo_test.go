// Copyright 2025 Mia srl
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

package custom_builtins

import (
	"context"
	"errors"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/stretchr/testify/require"
)

func prepareContext(t *testing.T, mongoClientMock *mocks.MongoClientMock) rego.BuiltinContext {
	t.Helper()

	ctx := context.Background()

	if mongoClientMock != nil {
		ctx = WithMongoClient(ctx, mongoClientMock)
	}

	return rego.BuiltinContext{
		Context: ctx,
	}
}

func TestMongoFindOneDefinition(t *testing.T) {
	defaultMock := &mocks.MongoClientMock{}

	t.Run("returns error if mongo client is not set", func(t *testing.T) {
		_, err := mongoFindOneDef(
			prepareContext(t, nil),
			nil,
			nil,
		)
		require.ErrorContains(t, err, "mongo client not set")
	})

	t.Run("returns error if mongo client in context is not valid", func(t *testing.T) {
		_, err := mongoFindOneDef(
			rego.BuiltinContext{
				Context: context.WithValue(context.Background(), mongoClientCustomBuiltinContextKey{}, "not a valid client"),
			},
			nil,
			nil,
		)
		require.ErrorContains(t, err, "no MongoDB client found in context")
	})

	t.Run("returns error if collection name is not a string", func(t *testing.T) {
		_, err := mongoFindOneDef(
			prepareContext(t, defaultMock),
			ast.BooleanTerm(false),
			nil,
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns error if query is not an object", func(t *testing.T) {
		_, err := mongoFindOneDef(prepareContext(
			t,
			defaultMock),
			ast.StringTerm("coll"),
			ast.BooleanTerm(false),
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns error if FindOne returns an error", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.MongoClientMock{
			FindOneError: errors.New("some error"),
			FindOneExpectation: func(collectionName string, query interface{}) {
				assertionInvoked = true
				require.Equal(t, "coll", collectionName)
				require.Equal(t, map[string]interface{}{}, query)
			},
		}
		_, err := mongoFindOneDef(
			prepareContext(t, mock),
			ast.StringTerm("coll"),
			ast.MustParseTerm("{}"),
		)
		require.ErrorContains(t, err, "some error")
		require.True(t, assertionInvoked)
	})
}
