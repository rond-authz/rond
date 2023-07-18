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

package sdk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/logging/test"
	"github.com/rond-authz/rond/metrics"
	metricstest "github.com/rond-authz/rond/metrics/test"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestEvaluateRequestPolicy(t *testing.T) {
	logger := logging.NewNoOpLogger()

	t.Run("throws without RondInput", func(t *testing.T) {
		sdk := getOASSdk(t, nil)
		evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
		require.NoError(t, err)

		_, err = evaluator.EvaluateRequestPolicy(context.Background(), nil, types.User{})
		require.EqualError(t, err, "RondInput cannot be empty")
	})

	type testCase struct {
		method           string
		path             string
		opaModuleContent string
		oasFilePath      string
		user             types.User
		reqHeaders       map[string]string
		mongoClient      types.IMongoClient

		expectedPolicy PolicyResult
		expectedErr    error
	}

	t.Run("evaluate request", func(t *testing.T) {
		testCases := map[string]testCase{
			"with empty user with policy true": {
				method: http.MethodGet,
				path:   "/users/",

				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte{},
				},
			},
			"with user with policy true": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
				},

				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte{},
				},
			},
			"not allow if not existing policy": {
				method: http.MethodPost,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
				},

				expectedPolicy: PolicyResult{},
				expectedErr:    core.ErrPolicyEvalFailed,
			},
			"not allowed policy result": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
				},
				opaModuleContent: `package policies todo { false }`,

				expectedPolicy: PolicyResult{},
				expectedErr:    core.ErrPolicyEvalFailed,
			},
			"with empty filter query": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: types.User{
					UserGroups: []string{"my-group"},
				},
				reqHeaders: map[string]string{
					"my-header-key": "ok",
				},
				opaModuleContent: `
				package policies
				generate_filter {
					input.user.groups[0] == "my-group"
					get_header("my-header-key", input.request.headers) == "ok"

					query := data.resources[_]
				}`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte(""),
				},
			},
			"with filter query": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: types.User{
					UserGroups: []string{"my-group"},
				},
				reqHeaders: map[string]string{
					"my-header-key": "ok",
				},
				opaModuleContent: `
				package policies
				generate_filter {
					query := data.resources[_]
					query.filterField == "my-filter-value"
				}`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte(`{"$or":[{"$and":[{"filterField":{"$eq":"my-filter-value"}}]}]}`),
				},
			},
			"check user": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserGroups: []string{"my-group"},
					UserRoles: []types.Role{
						{
							RoleID: "rid",
						},
					},
					UserBindings: []types.Binding{
						{
							Resource: &types.Resource{
								ResourceType: "my-resource",
							},
						},
					},
					Properties: map[string]any{
						"prop1": "my-user-field",
					},
				},
				opaModuleContent: `package policies
				todo {
					input.user.groups[0] == "my-group"
					input.user.roles[0].roleId == "rid"
					input.user.bindings[0].resource.resourceType == "my-resource"
					input.user.properties.prop1 == "my-user-field"
				}`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte(""),
				},
			},
			"with mongo client and find_one": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
				},
				opaModuleContent: `package policies
				todo {
					project := find_one("my-collection", {"myField": "1234"})
					project.myField == "1234"
				}
				`,
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte{},
				},
			},
			"with mongo client and find_one with dynamic find_one query": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
					Properties: map[string]any{
						"field": "1234",
					},
				},
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				opaModuleContent: `package policies
				todo {
					field := input.user.properties.field
					field == "1234"
					project := find_one("my-collection", {"myField": field})
					project.myField == "1234"
				}
				`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte{},
				},
			},
			"with mongo client and find_many": {
				method: http.MethodGet,
				path:   "/users/",
				user: types.User{
					UserID: "my-user",
				},
				mongoClient: &mocks.MongoClientMock{
					FindManyResult: []interface{}{
						map[string]interface{}{"myField": "1234"},
					},
					FindManyExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				opaModuleContent: `package policies
					todo {
						project := find_many("my-collection", {"myField": "1234"})
						project[0].myField == "1234"
					}
				`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte{},
				},
			},
			"with query and mongo client": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: types.User{
					UserGroups: []string{"my-group"},
				},
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				opaModuleContent: `
				package policies
				generate_filter {
					project := find_one("my-collection", {"myField": "1234"})

					query := data.resources[_]
					query.filterField == "1234"
				}`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte(`{"$or":[{"$and":[{"filterField":{"$eq":"1234"}}]}]}`),
				},
			},
			"with query and mongo client with dynamic find_one query": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: types.User{
					UserID: "my-user",
					Properties: map[string]any{
						"field": "1234",
					},
				},
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				opaModuleContent: `
				package policies
				generate_filter {
					field := input.user.properties.field
					field == "1234"
					project := find_one("my-collection", {"myField": field})

					query := data.resources[_]
					query.filterField == project.myField
				}`,
				expectedPolicy: PolicyResult{
					Allowed:      true,
					QueryToProxy: []byte(`{"$or":[{"$and":[{"filterField":{"$eq":"1234"}}]}]}`),
				},
			},
		}

		for name, testCase := range testCases {
			t.Run(name, func(t *testing.T) {
				testMetrics, hook := metricstest.New()
				sdk := getOASSdk(t, &sdkOptions{
					opaModuleContent: testCase.opaModuleContent,
					oasFilePath:      testCase.oasFilePath,
					mongoClient:      testCase.mongoClient,
					metrics:          testMetrics,
				})

				logger := test.GetLogger()
				evaluate, err := sdk.FindEvaluator(logger, testCase.method, testCase.path)
				require.NoError(t, err)

				headers := http.Header{}
				if testCase.reqHeaders != nil {
					for k, v := range testCase.reqHeaders {
						headers.Set(k, v)
					}
				}
				rondInput := getFakeInput(t, core.InputRequest{
					Headers: headers,
					Path:    testCase.path,
					Method:  testCase.method,
				}, "")

				actual, err := evaluate.EvaluateRequestPolicy(context.Background(), rondInput, testCase.user)
				if testCase.expectedErr != nil {
					require.EqualError(t, err, testCase.expectedErr.Error())
				} else {
					require.NoError(t, err)
				}
				require.Equal(t, testCase.expectedPolicy, actual)

				t.Run("logger", func(t *testing.T) {
					var actualEntry test.Record
					records, err := test.GetRecords(logger)
					require.NoError(t, err)
					for _, entry := range records {
						if entry.Message == "policy evaluation completed" {
							actualEntry = entry
						}
					}
					evaluatorInfo := evaluate.(evaluator)

					require.NotNil(t, actual)
					delete(actualEntry.Fields, "evaluationTimeMicroseconds")

					resultLength := 1
					if !actual.Allowed {
						resultLength = 0
					}

					fields := map[string]any{
						"allowed":       actual.Allowed,
						"requestedPath": testCase.path,
						"matchedPath":   evaluatorInfo.policyEvaluationOptions.AdditionalLogFields["matchedPath"],
						"method":        testCase.method,
						"partialEval":   evaluate.Config().RequestFlow.GenerateQuery,
						"policyName":    evaluate.Config().RequestFlow.PolicyName,
					}

					if !evaluate.Config().RequestFlow.GenerateQuery {
						fields["resultsLength"] = resultLength
					}

					require.Equal(t, fields, actualEntry.Fields)
				})

				t.Run("metrics", func(t *testing.T) {
					require.Len(t, hook.AllEntries(), 1)
					require.Equal(t, metricstest.Entry{
						Name: "policy_evaluation_duration_milliseconds",
						Labels: metrics.Labels{
							"policy_name": evaluate.Config().RequestFlow.PolicyName,
						},
						Value: hook.Entries[0].Value,
					}, hook.Entries[0])
				})
			})
		}
	})
}

func TestEvaluateResponsePolicy(t *testing.T) {
	logger := logging.NewNoOpLogger()

	t.Run("throws without RondInput", func(t *testing.T) {
		sdk := getOASSdk(t, nil)
		evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
		require.NoError(t, err)

		_, err = evaluator.EvaluateResponsePolicy(context.Background(), nil, types.User{}, nil)
		require.EqualError(t, err, "RondInput cannot be empty")
	})

	type testCase struct {
		method           string
		path             string
		opaModuleContent string
		user             types.User
		reqHeaders       map[string]string
		mongoClient      types.IMongoClient

		decodedBody any

		expectedBody string
		expectedErr  error
		notAllowed   bool
	}

	t.Run("evaluate response", func(t *testing.T) {
		testCases := map[string]testCase{
			"with empty user and empty object": {
				method:      http.MethodGet,
				path:        "/users/",
				decodedBody: map[string]interface{}{},

				expectedBody: "{}",
			},
			"with body unchanged": {
				method: http.MethodGet,
				path:   "/users/",

				decodedBody: map[string]interface{}{"foo": "bar", "f1": "b1"},

				expectedBody: `{"f1":"b1","foo":"bar"}`,
			},
			"with body changed": {
				method: http.MethodGet,
				path:   "/users/",
				opaModuleContent: `
				package policies
				responsepolicy [body] {
					originalBody := input.response.body

					body := json.patch(originalBody, [{"op": "replace", "path": "f1", "value": "censored"}])
				}`,

				decodedBody: map[string]interface{}{"foo": "bar", "f1": "b1"},

				expectedBody: `{"f1":"censored","foo":"bar"}`,
			},
			"with policy failure": {
				method: http.MethodGet,
				path:   "/users/",
				opaModuleContent: `
				package policies
				responsepolicy [body] {
					false
					body := input.response.body
				}`,
				expectedErr:  core.ErrPolicyEvalFailed,
				expectedBody: "",
				notAllowed:   true,
			},
			"with mongo query and body changed": {
				method: http.MethodGet,
				path:   "/users/",
				opaModuleContent: `
				package policies
				responsepolicy [body] {
					originalBody := input.response.body
					project := find_one("my-collection", {"myField": "1234"})

					body := json.patch(originalBody, [
						{"op": "replace", "path": "f1", "value": "censored"},
						{"op": "add", "path": "some", "value": project.myField}
					])
				}`,
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},

				decodedBody: map[string]interface{}{"foo": "bar", "f1": "b1"},

				expectedBody: `{"f1":"censored","foo":"bar","some":"1234"}`,
			},
		}

		for name, testCase := range testCases {
			t.Run(name, func(t *testing.T) {
				opaModuleContent := `
				package policies
				responsepolicy [body] {
					body := input.response.body
				}`

				if testCase.opaModuleContent != "" {
					opaModuleContent = testCase.opaModuleContent
				}

				logger := test.GetLogger()
				testMetrics, hook := metricstest.New()
				sdk := getOASSdk(t, &sdkOptions{
					opaModuleContent: opaModuleContent,
					oasFilePath:      "../mocks/rondOasConfig.json",
					mongoClient:      testCase.mongoClient,
					metrics:          testMetrics,
				})

				evaluate, err := sdk.FindEvaluator(logger, testCase.method, testCase.path)
				require.NoError(t, err)

				req := httptest.NewRequest(testCase.method, testCase.path, nil)
				if testCase.reqHeaders != nil {
					for k, v := range testCase.reqHeaders {
						req.Header.Set(k, v)
					}
				}
				headers := http.Header{}
				if testCase.reqHeaders != nil {
					for k, v := range testCase.reqHeaders {
						headers.Set(k, v)
					}
				}
				rondInput := getFakeInput(t, core.InputRequest{
					Headers: headers,
					Path:    testCase.path,
					Method:  testCase.method,
				}, "")

				actual, err := evaluate.EvaluateResponsePolicy(context.Background(), rondInput, testCase.user, testCase.decodedBody)
				if testCase.expectedErr != nil {
					require.EqualError(t, err, testCase.expectedErr.Error())
				} else {
					require.NoError(t, err)
				}

				if testCase.expectedBody == "" {
					require.Empty(t, string(actual))
				} else {
					require.JSONEq(t, testCase.expectedBody, string(actual))
				}

				t.Run("logger", func(t *testing.T) {
					var actual test.Record
					records, err := test.GetRecords(logger)
					require.NoError(t, err)
					for _, entry := range records {
						if entry.Message == "policy evaluation completed" {
							actual = entry
						}
					}
					evaluatorInfo := evaluate.(evaluator)

					require.NotNil(t, actual)
					delete(actual.Fields, "evaluationTimeMicroseconds")
					require.Equal(t, map[string]any{
						"allowed":       !testCase.notAllowed,
						"requestedPath": testCase.path,
						"matchedPath":   evaluatorInfo.policyEvaluationOptions.AdditionalLogFields["matchedPath"],
						"method":        testCase.method,
						"partialEval":   false,
						"policyName":    evaluate.Config().ResponseFlow.PolicyName,
						"resultsLength": 1,
					}, actual.Fields)
				})

				t.Run("metrics", func(t *testing.T) {
					require.Len(t, hook.AllEntries(), 1)
					require.Equal(t, metricstest.Entry{
						Name: "policy_evaluation_duration_milliseconds",
						Labels: metrics.Labels{
							"policy_name": evaluate.Config().ResponseFlow.PolicyName,
						},
						Value: hook.Entries[0].Value,
					}, hook.Entries[0])
				})
			})
		}
	})
}

func BenchmarkEvaluateRequest(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")

	openAPISpec, err := openapi.LoadOASFile("../mocks/bench.json")
	require.NoError(b, err)

	logger := logging.NewNoOpLogger()
	sdk, err := NewFromOAS(context.Background(), moduleConfig, openAPISpec, &Options{
		EvaluatorOptions: &core.OPAEvaluatorOptions{
			MongoClient: testmongoMock,
		},
	})
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		headers := http.Header{}
		headers.Set("my-header", "value")
		recorder := httptest.NewRecorder()

		rondInput := getFakeInput(b, core.InputRequest{
			Path:    "/projects/project123",
			Headers: headers,
			Method:  http.MethodGet,
			PathParams: map[string]string{
				"projectId": "project123",
			},
		}, "")
		b.StartTimer()
		evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/projects/project123")
		require.NoError(b, err)
		evaluator.EvaluateRequestPolicy(context.Background(), rondInput, types.User{})
		b.StopTimer()
		require.Equal(b, http.StatusOK, recorder.Code)
	}
}

func getOASSdk(t require.TestingT, options *sdkOptions) OASEvaluatorFinder {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	logger := logging.NewNoOpLogger()
	if options == nil {
		options = &sdkOptions{}
	}

	var oasFilePath = "../mocks/simplifiedMock.json"
	if options.oasFilePath != "" {
		oasFilePath = options.oasFilePath
	}

	openAPISpec, err := openapi.LoadOASFile(oasFilePath)
	require.NoError(t, err)
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		todo { true }`,
	}
	if options.opaModuleContent != "" {
		opaModule.Content = options.opaModuleContent
	}

	sdk, err := NewFromOAS(context.Background(), opaModule, openAPISpec, &Options{
		Metrics: options.metrics,
		EvaluatorOptions: &core.OPAEvaluatorOptions{
			EnablePrintStatements: true,
			MongoClient:           options.mongoClient,
		},
		Logger: logger,
	})
	require.NoError(t, err)

	return sdk
}
