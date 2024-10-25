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

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/metrics"

	"github.com/stretchr/testify/require"
)

func TestPartialResultEvaluators(t *testing.T) {
	logger := logging.NewNoOpLogger()

	opaModule := MustNewOPAModuleConfig([]Module{
		{
			Name: "example.rego",
			Content: `package policies
		allow {
			true
		}
		deny {
			false
		}
		column_policy{
			false
		}
		`,
		},
	})
	rondInput := Input{
		Request:    InputRequest{},
		Response:   InputResponse{},
		User:       InputUser{},
		ClientType: "client-type",
	}

	t.Run("throws if request policy is empty", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "",
			},
		}

		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, nil)
		require.EqualError(t, err, fmt.Sprintf("%s: allow policy is required", ErrInvalidConfig))
	})

	t.Run("throws if OpaModuleConfig is nil", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "not_exist",
			},
		}

		err := partialEvaluators.AddFromConfig(context.Background(), logger, nil, rondConfig, nil)
		require.EqualError(t, err, fmt.Sprintf("%s: OPAModuleConfig must not be nil", ErrEvaluatorCreationFailed))
	})

	t.Run("correctly create partial evaluator", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "allow",
			},
			ResponseFlow: ResponseFlow{
				PolicyName: "column_policy",
			},
		}
		ctx := context.Background()

		err := partialEvaluators.AddFromConfig(ctx, logger, opaModule, rondConfig, nil)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["allow"])
		require.NotNil(t, partialEvaluators["column_policy"])

		t.Run("find and evaluate policy - request", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(ctx, "allow", nil)
			require.NoError(t, err)
			res, err := evaluator.Evaluate(logger, input, nil)
			require.NoError(t, err)
			require.Nil(t, res)
		})

		t.Run("find and evaluate policy - response fails", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(ctx, "column_policy", nil)
			require.NoError(t, err)
			_, err = evaluator.Evaluate(logger, input, nil)
			require.EqualError(t, err, ErrPolicyNotAllowed.Error())
		})
	})

	t.Run("correctly create with mongo client", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "allow_with_find_one",
			},
		}

		opaModule, err := LoadRegoModule("../mocks/rego-policies-with-mongo-builtins")
		require.NoError(t, err)

		evalOpts := OPAEvaluatorOptions{
			MongoClient: mocks.MongoClientMock{
				FindOneExpectation: func(collectionName string, query interface{}) {
					require.Equal(t, "projects", collectionName)
					require.Equal(t, map[string]interface{}{"projectId": "1234"}, query)
				},
				FindOneResult: map[string]string{
					"tenantId": "some-tenant",
				},
			},
		}

		err = partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, &evalOpts)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["allow_with_find_one"])

		rondInput := Input{
			Request: InputRequest{
				PathParams: map[string]string{
					"projectId": "1234",
				},
			},
			Response:   InputResponse{},
			User:       InputUser{},
			ClientType: "client-type",
		}

		t.Run("find and evaluate policy", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "allow_with_find_one", &evalOpts)
			require.NoError(t, err)
			res, query, err := evaluator.PolicyEvaluation(logger, input, nil)
			require.NoError(t, err)
			require.Empty(t, query)
			require.Empty(t, res)
		})
	})

	t.Run("correctly create with logger", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "allow",
			},
		}

		evalOpts := OPAEvaluatorOptions{
			Logger: logger,
		}

		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, &evalOpts)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["allow"])

		rondInput := Input{
			Request: InputRequest{
				PathParams: map[string]string{
					"projectId": "1234",
				},
			},
			Response:   InputResponse{},
			User:       InputUser{},
			ClientType: "client-type",
		}

		t.Run("find and evaluate policy", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "allow", &evalOpts)
			require.NoError(t, err)
			res, query, err := evaluator.PolicyEvaluation(logger, input, nil)
			require.NoError(t, err)
			require.Empty(t, query)
			require.Empty(t, res)
		})
	})

	t.Run("correctly create with mongo client with query generation", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "filter_projects",
				GenerateQuery: true,
			},
		}

		opaModule := MustNewOPAModuleConfig([]Module{
			{
				Name: "example.rego",
				Content: `
			package policies
			filter_projects {
				field := input.user.properties.field
				field == "1234"
				myCollDoc := find_one("my-collection", {"myField": field})
				myCollDoc

				query := data.resources[_]
				query.filterField == myCollDoc.filterField
			}
			`,
			},
		})

		evalOpts := OPAEvaluatorOptions{
			MongoClient: mocks.MongoClientMock{
				FindOneExpectation: func(collectionName string, query interface{}) {
					require.Equal(t, "my-collection", collectionName)
					require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
				},
				FindOneResult: map[string]string{
					"filterField": "something",
				},
			},
		}

		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, &evalOpts)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["filter_projects"])

		rondInput := Input{
			Request:  InputRequest{},
			Response: InputResponse{},
			User: InputUser{
				Properties: map[string]interface{}{
					"field": "1234",
				},
			},
			ClientType: "client-type",
		}

		t.Run("find and evaluate policy", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "filter_projects", &evalOpts)
			require.NoError(t, err)
			res, query, err := evaluator.PolicyEvaluation(logger, input, nil)
			require.NoError(t, err)
			require.Empty(t, res)

			actualQuery, err := json.Marshal(query)
			require.NoError(t, err)
			require.JSONEq(t, `{"$or":[{"$and":[{"filterField":{"$eq":"something"}}]}]}`, string(actualQuery))
		})
	})

	t.Run("with passed metrics", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName:    "filter_projects",
				GenerateQuery: true,
			},
		}

		opaModule := MustNewOPAModuleConfig([]Module{
			{
				Name: "example.rego",
				Content: `
			package policies
			filter_projects {
				field := input.user.properties.field
				field == "1234"
				myCollDoc := find_one("my-collection", {"myField": field})
				myCollDoc

				query := data.resources[_]
				query.filterField == myCollDoc.filterField
			}
			`,
			},
		})

		evalOpts := OPAEvaluatorOptions{
			MongoClient: mocks.MongoClientMock{
				FindOneExpectation: func(collectionName string, query interface{}) {
					require.Equal(t, "my-collection", collectionName)
					require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
				},
				FindOneResult: map[string]string{
					"filterField": "something",
				},
			},
		}

		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, &evalOpts)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["filter_projects"])

		rondInput := Input{
			Request:  InputRequest{},
			Response: InputResponse{},
			User: InputUser{
				Properties: map[string]interface{}{
					"field": "1234",
				},
			},
			ClientType: "client-type",
		}

		t.Run("find and evaluate policy", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "filter_projects", &evalOpts)
			require.NoError(t, err)
			opts := PolicyEvaluationOptions{
				Metrics: metrics.NoOpMetrics(),
			}
			res, query, err := evaluator.PolicyEvaluation(logger, input, &opts)
			require.NoError(t, err)
			require.Empty(t, res)

			actualQuery, err := json.Marshal(query)
			require.NoError(t, err)
			require.JSONEq(t, `{"$or":[{"$and":[{"filterField":{"$eq":"something"}}]}]}`, string(actualQuery))
		})
	})

	t.Run("evaluation fails", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "deny",
			},
		}
		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, nil)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["deny"])

		t.Run("find and evaluate policy - request", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "deny", nil)
			require.NoError(t, err)
			_, _, err = evaluator.PolicyEvaluation(logger, input, nil)
			require.EqualError(t, err, ErrPolicyNotAllowed.Error())
		})
	})

	t.Run("evaluate policy with custom metadata", func(t *testing.T) {
		partialEvaluators := PartialResultsEvaluators{}
		rondConfig := &RondConfig{
			RequestFlow: RequestFlow{
				PolicyName: "check_metadata",
			},
		}

		evalOpts := OPAEvaluatorOptions{
			Logger: logger,
		}

		opaModule := MustNewOPAModuleConfig([]Module{
			{
				Name: "example.rego",
				Content: `package policies
			check_metadata {
				input.metadata.field == "ok"
			}`,
			},
		})

		err := partialEvaluators.AddFromConfig(context.Background(), logger, opaModule, rondConfig, &evalOpts)
		require.NoError(t, err)
		require.NotNil(t, partialEvaluators["allow"])

		rondInput := Input{
			CustomMetadata: map[string]any{
				"field": "ok",
			},
		}

		input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
		require.NoError(t, err)
		evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "check_metadata", &evalOpts)
		require.NoError(t, err)
		res, query, err := evaluator.PolicyEvaluation(logger, input, nil)
		require.NoError(t, err)
		require.Empty(t, query)
		require.Empty(t, res)
	})
}
