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
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	inputBytes, _ := json.Marshal(input)
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, _ := newQueryOPAEvaluator(context.Background(), "very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, inputBytes, nil)

		result, err := evaluator.PolicyEvaluator.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.PolicyEvaluator.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
	})
}

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

func TestCreateQueryEvaluator(t *testing.T) {
	policy := `package policies
allow {
	true
}
column_policy{
	false
}
`
	permission := RondConfig{
		RequestFlow: RequestFlow{
			PolicyName: "allow",
		},
		ResponseFlow: ResponseFlow{
			PolicyName: "column_policy",
		},
	}

	opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}

	logger := logging.NewNoOpLogger()

	input := Input{Request: InputRequest{}, Response: InputResponse{}}
	inputBytes, _ := json.Marshal(input)

	t.Run("create evaluator with allowPolicy", func(t *testing.T) {
		evaluator, err := opaModuleConfig.CreateQueryEvaluator(context.Background(), logger, permission.RequestFlow.PolicyName, inputBytes, nil)
		require.True(t, evaluator != nil)
		require.NoError(t, err, "Unexpected status code.")
	})

	t.Run("create  evaluator with policy for column filtering", func(t *testing.T) {
		evaluator, err := opaModuleConfig.CreateQueryEvaluator(context.Background(), logger, permission.ResponseFlow.PolicyName, inputBytes, nil)
		require.True(t, evaluator != nil)
		require.NoError(t, err, "Unexpected status code.")
	})
}

func TestGetHeaderFunction(t *testing.T) {
	headerKeyMocked := "exampleKey"
	headerValueMocked := "value"

	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		todo { get_header("ExAmPlEkEy", input.headers) == "value" }`,
	}
	queryString := "todo"

	t.Run("if header key exists", func(t *testing.T) {
		headers := http.Header{}
		headers.Add(headerKeyMocked, headerValueMocked)
		input := map[string]interface{}{
			"headers": headers,
		}
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := newQueryOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, results.Allowed(), "The input is not allowed by rego")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 1, "Rego policy allows illegal input")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := newQueryOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 0, "Rego policy allows illegal input")
	})
}
