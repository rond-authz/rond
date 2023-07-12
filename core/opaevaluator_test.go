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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/types"

	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	inputBytes, _ := json.Marshal(input)
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, _ := NewOPAEvaluator(context.Background(), "very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, inputBytes, nil)

		result, err := evaluator.PolicyEvaluator.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.PolicyEvaluator.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
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

	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

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

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrintHook(&buf, "policy-name")

	err := h.Print(print.Context{}, "the print message")
	require.NoError(t, err)

	var re = regexp.MustCompile(`"time":\d+`)
	require.JSONEq(t, `{"level":10,"msg":"the print message","time":123,"policyName":"policy-name"}`, string(re.ReplaceAll(buf.Bytes(), []byte("\"time\":123"))))
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

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
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

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 0, "Rego policy allows illegal input")
	})
}

func TestPartialResultEvaluators(t *testing.T) {
	// log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(logrus.New())

	opaModule := &OPAModuleConfig{
		Content: `package policies
		allow {
			true
		}
		column_policy{
			false
		}
		`,
		Name: "policies",
	}
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
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(ctx, "allow", input, nil)
			require.NoError(t, err)
			res, err := evaluator.Evaluate(logger, nil)
			require.NoError(t, err)
			require.Nil(t, res)
		})

		t.Run("find and evaluate policy - response fails", func(t *testing.T) {
			input, err := CreateRegoQueryInput(logger, rondInput, RegoInputOptions{})
			require.NoError(t, err)
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(ctx, "column_policy", input, nil)
			require.NoError(t, err)
			_, err = evaluator.Evaluate(logger, nil)
			require.EqualError(t, err, ErrPolicyEvalFailed.Error())
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
			evaluator, err := partialEvaluators.GetEvaluatorFromPolicy(context.Background(), "allow_with_find_one", input, &evalOpts)
			require.NoError(t, err)
			res, query, err := evaluator.PolicyEvaluation(logger, rondConfig, nil)
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

		opaModule := &OPAModuleConfig{
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
		}

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
			evaluator, err := opaModule.CreateQueryEvaluator(context.Background(), logger, "filter_projects", input, &evalOpts)
			require.NoError(t, err)
			res, query, err := evaluator.PolicyEvaluation(logger, rondConfig, nil)
			require.NoError(t, err)
			require.Empty(t, res)

			var actualQuery = []byte{}
			actualQuery, err = json.Marshal(query)
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

		opaModule := &OPAModuleConfig{
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
		}

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
			evaluator, err := opaModule.CreateQueryEvaluator(context.Background(), logger, "filter_projects", input, &evalOpts)
			require.NoError(t, err)
			metrics := metrics.SetupMetrics("rond")
			opts := PolicyEvaluationOptions{
				Metrics: &metrics,
			}
			res, query, err := evaluator.PolicyEvaluation(logger, rondConfig, &opts)
			require.NoError(t, err)
			require.Empty(t, res)

			var actualQuery = []byte{}
			actualQuery, err = json.Marshal(query)
			require.NoError(t, err)
			require.JSONEq(t, `{"$or":[{"$and":[{"filterField":{"$eq":"something"}}]}]}`, string(actualQuery))
		})
	})
}
