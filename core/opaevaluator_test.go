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

package core

import (
	"context"
	"testing"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestOPAEvaluator(t *testing.T) {
	t.Run("get context", func(t *testing.T) {
		t.Run("no context", func(t *testing.T) {
			opaEval := OPAEvaluator{}
			ctx := opaEval.getContext()

			require.NotNil(t, ctx)
			client, err := custom_builtins.GetMongoClientFromContext(ctx)
			require.NoError(t, err)
			require.Nil(t, client)

			logger := logging.FromContext(ctx)
			require.NotNil(t, logger)
		})

		t.Run("passed context with mongo client", func(t *testing.T) {
			mongoClient := mocks.MongoClientMock{}
			originalContext := custom_builtins.WithMongoClient(context.Background(), mongoClient)
			opaEval := OPAEvaluator{
				context: originalContext,
			}
			ctx := opaEval.getContext()

			require.NotNil(t, ctx)
			client, err := custom_builtins.GetMongoClientFromContext(ctx)
			require.NoError(t, err)
			require.Equal(t, mongoClient, client)
		})

		t.Run("passed mongo client", func(t *testing.T) {
			mongoClient := mocks.MongoClientMock{}
			opaEval := OPAEvaluator{
				context:     context.Background(),
				mongoClient: mongoClient,
			}
			ctx := opaEval.getContext()

			require.NotNil(t, ctx)
			client, err := custom_builtins.GetMongoClientFromContext(ctx)
			require.NoError(t, err)
			require.Equal(t, mongoClient, client)
		})

		t.Run("passed logger", func(t *testing.T) {
			log := logging.NewNoOpLogger()
			opaEval := OPAEvaluator{
				context: context.Background(),
				logger:  log,
			}
			ctx := opaEval.getContext()

			require.NotNil(t, ctx)
			actualLog := logging.FromContext(ctx)
			require.Equal(t, log, actualLog)
		})
	})

	t.Run("PolicyEvaluation", func(t *testing.T) {
		t.Run("with empty evaluator - generate query", func(t *testing.T) {
			opaEval := OPAEvaluator{
				generateQuery: true,
			}
			logger := logging.NewNoOpLogger()
			result, query, err := opaEval.PolicyEvaluation(logger, nil, nil)

			require.EqualError(t, err, "partial policy evaluation failed: preparedPartialQuery is nil")
			require.Nil(t, result)
			require.Empty(t, query)
		})

		t.Run("with empty evaluator - eval query", func(t *testing.T) {
			opaEval := OPAEvaluator{}
			logger := logging.NewNoOpLogger()
			result, query, err := opaEval.PolicyEvaluation(logger, nil, nil)

			require.EqualError(t, err, "policy evaluation failed: preparedEvalQuery is nil")
			require.Nil(t, result)
			require.Empty(t, query)
		})
	})
}

func TestBuildRolesMap(t *testing.T) {
	roles := []types.Role{
		{
			RoleID:      "role1",
			Permissions: []string{"permission1", "permission2"},
		},
		{
			RoleID:      "role2",
			Permissions: []string{"permission3", "permission4"},
		},
	}
	result := buildRolesMap(roles)
	expected := map[string][]string{
		"role1": {"permission1", "permission2"},
		"role2": {"permission3", "permission4"},
	}
	require.Equal(t, expected, result)
}
