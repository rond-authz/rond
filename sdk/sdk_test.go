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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestNewSDK(t *testing.T) {
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}

	t.Run("fails if oas is nil", func(t *testing.T) {
		sdk, err := New(context.Background(), logger, nil, nil, nil, nil, "")
		require.ErrorContains(t, err, "oas must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("fails if opaModuleConfig is nil", func(t *testing.T) {
		sdk, err := New(context.Background(), logger, openAPISpec, nil, nil, nil, "")
		require.ErrorContains(t, err, "OPAModuleConfig must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("fails if oas is invalid", func(t *testing.T) {
		oas, err := openapi.LoadOASFile("../mocks/invalidOASConfiguration.json")
		require.NoError(t, err)
		sdk, err := New(context.Background(), logger, oas, opaModule, nil, nil, "")
		require.ErrorContains(t, err, "invalid OAS configuration:")
		require.Nil(t, sdk)
	})

	t.Run("creates sdk correctly", func(t *testing.T) {
		sdk, err := New(context.Background(), logger, openAPISpec, opaModule, nil, nil, "")
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
	})

	t.Run("if registry is passed, setup metrics", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		sdk, err := New(context.Background(), logger, openAPISpec, opaModule, nil, registry, "")
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
	})
}

func TestSDK(t *testing.T) {
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}
	registry := prometheus.NewRegistry()
	sdk, err := New(context.Background(), logger, openAPISpec, opaModule, nil, registry, "")
	require.NoError(t, err)

	rond, ok := sdk.(rondImpl)
	require.True(t, ok, "rondImpl is not sdk")

	t.Run("FindEvaluator", func(t *testing.T) {
		t.Run("throws if path and method not found", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/not-existent/path")
			require.ErrorContains(t, err, "not found oas definition: GET /not-existent/path")
			require.Nil(t, actual)
		})

		t.Run("returns correct evaluator", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			evaluatorOptions := &core.EvaluatorOptions{
				Metrics: rond.evaluatorOptions.Metrics,
				RouterInfo: openapi.RouterInfo{
					MatchedPath:   "/users/",
					RequestedPath: "/users/",
					Method:        http.MethodGet,
				},
			}
			require.Equal(t, evaluator{
				rondConfig: openapi.RondConfig{
					RequestFlow: openapi.RequestFlow{
						PolicyName: "todo",
					},
				},
				opaModuleConfig:         opaModule,
				partialResultEvaluators: rond.partialResultEvaluators,
				logger:                  logger,
				evaluatorOptions:        evaluatorOptions,
			}, actual)

			t.Run("get permissions", func(t *testing.T) {
				require.Equal(t, openapi.RondConfig{
					RequestFlow: openapi.RequestFlow{
						PolicyName: "todo",
					},
				}, actual.Config())
			})
		})
	})
}

func TestEvaluateRequestPolicy(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	t.Run("throws without RondInput", func(t *testing.T) {
		sdk := getSdk(t, nil)
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
				mongoClient: &mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
				opaModuleContent: `package policies
					todo {
						project := find_one("my-collection", {"myField": "1234"})
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
				reqHeaders: map[string]string{
					"my-header-key": "ok",
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
		}

		for name, testCase := range testCases {
			t.Run(name, func(t *testing.T) {
				registry := prometheus.NewPedanticRegistry()
				sdk := getSdk(t, &sdkOptions{
					opaModuleContent: testCase.opaModuleContent,
					oasFilePath:      testCase.oasFilePath,
					mongoClient:      testCase.mongoClient,
					registry:         registry,
				})

				log, hook := test.NewNullLogger()
				log.Level = logrus.DebugLevel
				logger := logrus.NewEntry(log)
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
					var actualEntry *logrus.Entry
					for _, entry := range hook.AllEntries() {
						if entry.Message == "policy evaluation completed" {
							actualEntry = entry
						}
					}
					evaluatorInfo := evaluate.(evaluator)

					require.NotNil(t, actual)
					delete(actualEntry.Data, "evaluationTimeMicroseconds")

					resultLength := 1
					if !actual.Allowed {
						resultLength = 0
					}

					fields := logrus.Fields{
						"allowed":       actual.Allowed,
						"requestedPath": testCase.path,
						"matchedPath":   evaluatorInfo.evaluatorOptions.RouterInfo.MatchedPath,
						"method":        testCase.method,
						"partialEval":   evaluate.Config().RequestFlow.GenerateQuery,
						"policyName":    evaluate.Config().RequestFlow.PolicyName,
					}

					if !evaluate.Config().RequestFlow.GenerateQuery {
						fields["resultsLength"] = resultLength
					}

					require.Equal(t, fields, actualEntry.Data)
				})

				t.Run("metrics", func(t *testing.T) {
					expected := fmt.Sprintf(`rond_policy_evaluation_duration_milliseconds_count{policy_name="%s"} 1`, evaluate.Config().RequestFlow.PolicyName)
					assertCorrectMetrics(t, registry, expected)
				})
			})
		}
	})
}

func assertCorrectMetrics(t *testing.T, registry *prometheus.Registry, expected string) {
	t.Helper()

	g := prometheus.ToTransactionalGatherer(registry)
	got, done, err := g.Gather()
	defer done()
	require.NoError(t, err)

	for _, m := range got {
		if m.GetName() == "rond_policy_evaluation_duration_milliseconds" {
			var gotBuf bytes.Buffer
			enc := expfmt.NewEncoder(&gotBuf, expfmt.FmtText)
			err := enc.Encode(m)
			require.NoError(t, err)
			require.Contains(t, gotBuf.String(), expected)
			return
		}
	}
	require.Fail(t, "metrics must be retrieved")
}

func TestEvaluateResponsePolicy(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	t.Run("throws without RondInput", func(t *testing.T) {
		sdk := getSdk(t, nil)
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

				log, hook := test.NewNullLogger()
				log.Level = logrus.DebugLevel
				logger := logrus.NewEntry(log)
				registry := prometheus.NewPedanticRegistry()
				sdk := getSdk(t, &sdkOptions{
					opaModuleContent: opaModuleContent,
					oasFilePath:      "../mocks/rondOasConfig.json",
					mongoClient:      testCase.mongoClient,
					registry:         registry,
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
					var actual *logrus.Entry
					for _, entry := range hook.AllEntries() {
						if entry.Message == "policy evaluation completed" {
							actual = entry
						}
					}
					evaluatorInfo := evaluate.(evaluator)

					require.NotNil(t, actual)
					delete(actual.Data, "evaluationTimeMicroseconds")
					require.Equal(t, logrus.Fields{
						"allowed":       !testCase.notAllowed,
						"requestedPath": testCase.path,
						"matchedPath":   evaluatorInfo.evaluatorOptions.RouterInfo.MatchedPath,
						"method":        testCase.method,
						"partialEval":   false,
						"policyName":    evaluate.Config().ResponseFlow.PolicyName,
						"resultsLength": 1,
					}, actual.Data)
				})

				t.Run("metrics", func(t *testing.T) {
					expected := fmt.Sprintf(`rond_policy_evaluation_duration_milliseconds_count{policy_name="%s"} 1`, evaluate.Config().ResponseFlow.PolicyName)
					assertCorrectMetrics(t, registry, expected)
				})
			})
		}
	})
}

func TestContext(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		rondConfig := openapi.RondConfig{
			RequestFlow: openapi.RequestFlow{
				PolicyName:    "todo",
				GenerateQuery: true,
			},
			ResponseFlow: openapi.ResponseFlow{
				PolicyName: "other",
			},
		}

		expectedEvaluator := evaluator{
			rondConfig: rondConfig,
		}

		ctx = WithEvaluatorSDK(ctx, expectedEvaluator)

		actualEvaluator, err := GetEvaluatorSKD(ctx)
		require.NoError(t, err)
		require.Equal(t, expectedEvaluator, actualEvaluator)
	})

	t.Run("throws if not in context", func(t *testing.T) {
		actualEvaluator, err := GetEvaluatorSKD(context.Background())
		require.EqualError(t, err, "no SDKEvaluator found in request context")
		require.Nil(t, actualEvaluator)
	})
}

func BenchmarkEvaluateRequest(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")

	openAPISpec, err := openapi.LoadOASFile("../mocks/bench.json")
	require.NoError(b, err)

	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)
	sdk, err := New(context.Background(), logger, openAPISpec, moduleConfig, &core.EvaluatorOptions{
		MongoClient: testmongoMock,
	}, nil, "")
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

type sdkOptions struct {
	opaModuleContent string
	oasFilePath      string

	mongoClient types.IMongoClient
	registry    *prometheus.Registry
}

type tHelper interface {
	Helper()
}

func getSdk(t require.TestingT, options *sdkOptions) Rond {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	logger := logrus.NewEntry(logrus.New())
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
	sdk, err := New(context.Background(), logger, openAPISpec, opaModule, &core.EvaluatorOptions{
		EnablePrintStatements: true,
		MongoClient:           options.mongoClient,
	}, options.registry, "")
	require.NoError(t, err)

	return sdk
}

var testmongoMock = &mocks.MongoClientMock{
	UserBindings: []types.Binding{
		{
			BindingID:   "binding1",
			Subjects:    []string{"user1"},
			Roles:       []string{"admin"},
			Groups:      []string{"area_rocket"},
			Permissions: []string{"permission4"},
			Resource: &types.Resource{
				ResourceType: "project",
				ResourceID:   "project123",
			},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group4"},
			Permissions:       []string{"permission7"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding3",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission10", "permission4"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding4",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group2"},
			Permissions:       []string{"permission11"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "bindingForRowFiltering",
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "9876"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "bindingForRowFilteringFromSubject",
			Subjects:          []string{"filter_test"},
			Roles:             []string{"role3", "role4"},
			Groups:            []string{"group1"},
			Permissions:       []string{"console.project.view"},
			Resource:          &types.Resource{ResourceType: "custom", ResourceID: "12345"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "binding5",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permission12"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "notUsedByAnyone",
			Subjects:          []string{"user5"},
			Roles:             []string{"role3", "role4"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			BindingID:         "notUsedByAnyone2",
			Subjects:          []string{"user1"},
			Roles:             []string{"role3", "role6"},
			Permissions:       []string{"permissionNotUsed"},
			CRUDDocumentState: "PRIVATE",
		},
	},
	UserRoles: []types.Role{
		{
			RoleID:            "admin",
			Permissions:       []string{"console.project.view", "permission2", "foobar"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			RoleID:            "role3",
			Permissions:       []string{"permission3", "permission5", "console.project.view"},
			CRUDDocumentState: "PUBLIC",
		},
		{
			RoleID:            "role6",
			Permissions:       []string{"permission3", "permission5"},
			CRUDDocumentState: "PRIVATE",
		},
		{
			RoleID:            "notUsedByAnyone",
			Permissions:       []string{"permissionNotUsed1", "permissionNotUsed2"},
			CRUDDocumentState: "PUBLIC",
		},
	},
}

type FakeInput struct {
	request    core.InputRequest
	clientType string
}

func (i FakeInput) Input(user types.User, responseBody any) (core.Input, error) {
	return core.Input{
		User: core.InputUser{
			Properties: user.Properties,
			Groups:     user.UserGroups,
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
		},
		Request: i.request,
		Response: core.InputResponse{
			Body: responseBody,
		},
		ClientType: i.clientType,
	}, nil
}

func getFakeInput(t require.TestingT, request core.InputRequest, clientType string) core.RondInput {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	return FakeInput{
		request:    request,
		clientType: clientType,
	}
}
