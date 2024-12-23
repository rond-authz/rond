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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/logging/test"
	"github.com/rond-authz/rond/metrics"
	metricstest "github.com/rond-authz/rond/metrics/test"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestEvaluateRequestPolicy(t *testing.T) {
	type testCase struct {
		method           string
		path             string
		opaModuleContent string
		oasFilePath      string
		user             core.InputUser
		reqHeaders       map[string]string
		mongoClient      custom_builtins.IMongoClient
		enableAudit      bool

		expectedPolicy PolicyResult
		expectedErr    error

		expectedAuditLabels     map[string]any
		expectedAuditBindingID  string
		expectedAuditPermission string
		expectedAuditRoleID     string
	}

	t.Run("evaluate request", func(t *testing.T) {
		testCases := map[string]testCase{
			"with empty user with policy true": {
				method: http.MethodGet,
				path:   "/users/",
				expectedPolicy: PolicyResult{
					Allowed: true,
				},
			},
			"with user with policy true": {
				method: http.MethodGet,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
				},
				expectedPolicy: PolicyResult{
					Allowed: true,
				},
			},
			"not allow if not existing policy": {
				method: http.MethodPost,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
				},
				expectedPolicy: PolicyResult{},
			},
			"not allowed policy result": {
				method: http.MethodGet,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
				},
				opaModuleContent: `package policies todo { false }`,
				expectedPolicy:   PolicyResult{},
			},
			"with empty filter query": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: core.InputUser{
					Groups: []string{"my-group"},
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
					Allowed: true,
				},
			},
			"with filter query": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: core.InputUser{
					Groups: []string{"my-group"},
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
				user: core.InputUser{
					ID:     "the-user-id",
					Groups: []string{"my-group"},
					Roles: []types.Role{
						{
							RoleID: "rid",
						},
					},
					Bindings: []types.Binding{
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
					input.user.id == "the-user-id"
					input.user.groups[0] == "my-group"
					input.user.roles[0].roleId == "rid"
					input.user.bindings[0].resource.resourceType == "my-resource"
					input.user.properties.prop1 == "my-user-field"
				}`,
				expectedPolicy: PolicyResult{
					Allowed: true,
				},
			},
			"with mongo client and find_one": {
				method: http.MethodGet,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
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
					Allowed: true,
				},
			},
			"with mongo client and find_one with dynamic find_one query": {
				method: http.MethodGet,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
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
					Allowed: true,
				},
			},
			"with mongo client and find_many": {
				method: http.MethodGet,
				path:   "/users/",
				user: core.InputUser{
					ID: "my-user",
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
					Allowed: true,
				},
			},
			"with query and mongo client": {
				method:      http.MethodGet,
				path:        "/users/",
				oasFilePath: "../mocks/rondOasConfig.json",
				user: core.InputUser{
					Groups: []string{"my-group"},
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
				user: core.InputUser{
					ID: "my-user",
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
			"audit integration with successful policy": {
				method:         http.MethodGet,
				path:           "/users/",
				user:           core.InputUser{ID: "my-user"},
				expectedPolicy: PolicyResult{Allowed: true},
				enableAudit:    true,
			},
			"audit integration with custom labels": {
				method: http.MethodGet,
				path:   "/users/",
				user:   core.InputUser{ID: "my-user"},
				opaModuleContent: `package policies todo {
					set_audit_labels({
						"labelKey":"labelVal",
						"authorization.permission": "the-permission",
						"authorization.binding": "the-binding",
						"authorization.role": "the-roleid"
					})
					true
				}`,
				expectedPolicy:          PolicyResult{Allowed: true},
				enableAudit:             true,
				expectedAuditLabels:     map[string]any{"labelKey": "labelVal"},
				expectedAuditBindingID:  "the-binding",
				expectedAuditPermission: "the-permission",
				expectedAuditRoleID:     "the-roleid",
			},
			"audit integration with failed policy": {
				method: http.MethodGet,
				path:   "/users/",
				user:   core.InputUser{ID: "my-user"},
				opaModuleContent: `package policies todo {
					set_audit_labels({
						"labelKey":"labelVal",
						"authorization.permission": "the-permission",
						"authorization.binding": "the-binding",
						"authorization.role": "the-roleid"
					})
					false
				}`,
				expectedPolicy:          PolicyResult{},
				enableAudit:             true,
				expectedAuditLabels:     map[string]any{"labelKey": "labelVal"},
				expectedAuditBindingID:  "the-binding",
				expectedAuditPermission: "the-permission",
				expectedAuditRoleID:     "the-roleid",
			},
		}

		for name, testCase := range testCases {
			t.Run(name, func(t *testing.T) {
				testMetrics, hook := metricstest.New()

				testLogger := test.GetLogger()
				sdk := getOASSdk(t, &sdkOptions{
					opaModuleContent: testCase.opaModuleContent,
					oasFilePath:      testCase.oasFilePath,
					mongoClient:      testCase.mongoClient,
					metrics:          testMetrics,
					enableAudit:      testCase.enableAudit,
					logger:           testLogger,
				})

				evaluate, err := sdk.FindEvaluator(testCase.method, testCase.path)
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
				}, "", testCase.user, nil)

				logger := test.GetLogger()
				actual, err := evaluate.EvaluateRequestPolicy(context.Background(), rondInput, &EvaluateOptions{
					Logger: logger,
				})
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

				t.Run("audit", func(t *testing.T) {
					records, err := test.GetRecords(testLogger)
					require.NoError(t, err)

					trailRecords := []test.Record{}
					for _, record := range records {
						if record.Message == "audit trail" {
							trailRecords = append(trailRecords, record)
						}
					}

					expectedRecords := 0
					if testCase.enableAudit {
						expectedRecords = 1
					}

					require.Len(t, trailRecords, expectedRecords)

					if testCase.enableAudit {
						foundRecord := trailRecords[0].Fields["trail"].(map[string]any)
						require.NotEmpty(t, foundRecord["id"])
						delete(foundRecord, "id")

						authz := map[string]any{
							"allowed":    testCase.expectedPolicy.Allowed,
							"policyName": "todo",
						}
						if testCase.expectedAuditBindingID != "" {
							authz["binding"] = testCase.expectedAuditBindingID
						}
						if testCase.expectedAuditPermission != "" {
							authz["permission"] = testCase.expectedAuditPermission
						}
						if testCase.expectedAuditRoleID != "" {
							authz["roleId"] = testCase.expectedAuditRoleID
						}

						require.Equal(t, map[string]any{
							"authorization": authz,
							"labels":        testCase.expectedAuditLabels,
							"request": map[string]any{
								"path": testCase.path,
								"verb": testCase.method,
							},
							"subject": map[string]any{
								"id": "my-user",
							},
						}, trailRecords[0].Fields["trail"])
					}
				})
			})
		}

		t.Run("concurrent map writes with audit log (issue #418)", func(t *testing.T) {
			expectedAuditBindingID := "the-binding"
			expectedAuditPermission := "the-permission"
			expectedAuditRoleID := "the-roleid"

			opaModuleContent := fmt.Sprintf(`package policies todo {
				h1 := get_header("my-header-key", input.request.headers)
				set_audit_labels({
					"labelKey":"labelVal",
					"authorization.permission": "%s",
					"authorization.binding": "%s",
					"authorization.role": "%s",
					"My-Header-Key": h1
				})
				true
			}`, expectedAuditPermission, expectedAuditBindingID, expectedAuditRoleID)
			method := http.MethodGet
			path := "/users/"

			testCase := func(t *testing.T, evaluate Evaluator, headers http.Header) {
				t.Helper()

				rondInput := getFakeInput(t, core.InputRequest{
					Headers: headers,
					Path:    path,
					Method:  method,
				}, "", core.InputUser{ID: "my-user"}, nil)

				logger := test.GetLogger()
				actual, err := evaluate.EvaluateRequestPolicy(context.Background(), rondInput, &EvaluateOptions{
					Logger: logger,
				})
				require.NoError(t, err)
				expectedPolicy := PolicyResult{Allowed: true}
				require.Equal(t, expectedPolicy, actual)
			}

			t.Run("with NewFromOas", func(t *testing.T) {
				testLogger := test.GetLogger()
				sdk := getOASSdk(t, &sdkOptions{
					opaModuleContent: opaModuleContent,
					enableAudit:      true,
					logger:           testLogger,
				})

				wg := sync.WaitGroup{}

				wg.Add(1)
				go func() {
					evaluate, err := sdk.FindEvaluator(method, path)
					require.NoError(t, err)

					h := http.Header{}
					h.Set("My-Header-Key", "c1")
					testCase(t, evaluate, h)
					wg.Done()
				}()

				wg.Add(1)
				go func() {
					evaluate, err := sdk.FindEvaluator(method, path)
					require.NoError(t, err)

					h := http.Header{}
					h.Set("My-Header-Key", "c2")
					testCase(t, evaluate, h)
					wg.Done()
				}()

				wg.Wait()

				t.Run("audit", func(t *testing.T) {
					records, err := test.GetRecords(testLogger)
					require.NoError(t, err)

					trailRecords := []test.Record{}
					for _, record := range records {
						if record.Message == "audit trail" {
							trailRecords = append(trailRecords, record)
						}
					}

					require.Len(t, trailRecords, 2)
					expectedHeaderValues := map[string]bool{
						"c1": false,
						"c2": false,
					}

					for _, record := range trailRecords {
						trailRecord := record.Fields["trail"].(map[string]any)
						require.NotEmpty(t, trailRecord["id"])
						delete(trailRecord, "id")

						authz := map[string]any{
							"allowed":    true,
							"policyName": "todo",
							"binding":    expectedAuditBindingID,
							"permission": expectedAuditPermission,
							"roleId":     expectedAuditRoleID,
						}

						headerValue := trailRecord["labels"].(map[string]any)["My-Header-Key"].(string)
						if expectedHeaderValues[headerValue] {
							t.Errorf("header value %s already seen", headerValue)
						}
						expectedHeaderValues[headerValue] = true

						labels := map[string]any{
							"labelKey":      "labelVal",
							"My-Header-Key": headerValue,
						}

						require.Equal(t, map[string]any{
							"authorization": authz,
							"labels":        labels,
							"request": map[string]any{
								"path": path,
								"verb": method,
							},
							"subject": map[string]any{
								"id": "my-user",
							},
						}, trailRecord)
					}
				})
			})

			t.Run("with NewWithConfig", func(t *testing.T) {
				testLogger := test.GetLogger()
				config := core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName: "todo",
					},
				}

				opaModuleConfig := core.MustNewOPAModuleConfig([]core.Module{
					{Content: opaModuleContent},
				})

				evaluate, err := NewWithConfig(context.Background(), opaModuleConfig, config, &Options{
					EvaluatorOptions: &EvaluatorOptions{
						EnableAuditTracing:    true,
						EnablePrintStatements: true,
					},
					Logger: testLogger,
				})
				require.NoError(t, err)

				wg := sync.WaitGroup{}

				wg.Add(1)
				go func() {
					h := http.Header{}
					h.Set("My-Header-Key", "c1")
					testCase(t, evaluate, h)
					wg.Done()
				}()

				wg.Add(1)
				go func() {
					h1 := http.Header{}
					h1.Set("My-Header-Key", "c2")
					testCase(t, evaluate, h1)
					wg.Done()
				}()

				wg.Wait()

				t.Run("audit", func(t *testing.T) {
					records, err := test.GetRecords(testLogger)
					require.NoError(t, err)

					trailRecords := []test.Record{}
					for _, record := range records {
						if record.Message == "audit trail" {
							trailRecords = append(trailRecords, record)
						}
					}

					require.Len(t, trailRecords, 2)
					expectedHeaderValues := map[string]bool{
						"c1": false,
						"c2": false,
					}

					for _, record := range trailRecords {
						trailRecord := record.Fields["trail"].(map[string]any)
						require.NotEmpty(t, trailRecord["id"])
						delete(trailRecord, "id")

						authz := map[string]any{
							"allowed":    true,
							"policyName": "todo",
							"binding":    expectedAuditBindingID,
							"permission": expectedAuditPermission,
							"roleId":     expectedAuditRoleID,
						}

						headerValue := trailRecord["labels"].(map[string]any)["My-Header-Key"].(string)
						if expectedHeaderValues[headerValue] {
							t.Errorf("header value %s already seen", headerValue)
						}
						expectedHeaderValues[headerValue] = true

						labels := map[string]any{
							"labelKey":      "labelVal",
							"My-Header-Key": headerValue,
						}

						require.Equal(t, map[string]any{
							"authorization": authz,
							"labels":        labels,
							"request": map[string]any{
								"path": path,
								"verb": method,
							},
							"subject": map[string]any{
								"id": "my-user",
							},
						}, trailRecord)
					}
				})
			})
		})
	})

	t.Run("with nil options", func(t *testing.T) {
		opaModule := core.MustNewOPAModuleConfig([]core.Module{
			{
				Name:    "example.rego",
				Content: `package policies todo { true }`,
			},
		})

		sdk, err := NewWithConfig(context.Background(), opaModule, core.RondConfig{
			RequestFlow: core.RequestFlow{PolicyName: "todo"},
		}, nil)
		require.NoError(t, err)

		result, err := sdk.EvaluateRequestPolicy(context.Background(), core.Input{}, nil)
		require.NoError(t, err)
		require.Equal(t, PolicyResult{
			Allowed: true,
		}, result)
	})
}

func TestEvaluateResponsePolicy(t *testing.T) {
	type testCase struct {
		method           string
		path             string
		opaModuleContent string
		user             core.InputUser
		reqHeaders       map[string]string
		mongoClient      custom_builtins.IMongoClient
		enableAudit      bool

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
				expectedErr:  core.ErrPolicyNotAllowed,
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
			"audit integration with allowed policy": {
				method:      http.MethodGet,
				path:        "/users/",
				decodedBody: map[string]interface{}{},
				enableAudit: true,

				expectedBody: "{}",
			},
			"audit integration with failed policy": {
				method:      http.MethodGet,
				path:        "/users/",
				decodedBody: map[string]interface{}{},
				opaModuleContent: `
				package policies
				responsepolicy [body] {
					false
					body := input.response.body
				}`,
				expectedBody: "",
				expectedErr:  core.ErrPolicyNotAllowed,
				notAllowed:   true,
				enableAudit:  true,
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
					enableAudit:      testCase.enableAudit,
					logger:           logger,
				})

				evaluate, err := sdk.FindEvaluator(testCase.method, testCase.path)
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
				}, "", testCase.user, testCase.decodedBody)

				actual, err := evaluate.EvaluateResponsePolicy(context.Background(), rondInput, &EvaluateOptions{
					Logger: logger,
				})
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

				t.Run("audit", func(t *testing.T) {
					records, err := test.GetRecords(logger)
					require.NoError(t, err)

					trailRecords := []test.Record{}
					for _, record := range records {
						if record.Message == "audit trail" {
							trailRecords = append(trailRecords, record)
						}
					}

					expectedRecords := 0
					if testCase.enableAudit {
						expectedRecords = 1
					}
					require.Len(t, trailRecords, expectedRecords)

					if testCase.enableAudit {
						foundRecord := trailRecords[0].Fields["trail"].(map[string]any)
						require.NotEmpty(t, foundRecord["id"])
						delete(foundRecord, "id")

						var labels map[string]any
						require.Equal(t, map[string]any{
							"authorization": map[string]any{
								"allowed":    !testCase.notAllowed,
								"policyName": "responsepolicy",
							},
							"labels": labels,
							"request": map[string]any{
								"path": testCase.path,
								"verb": testCase.method,
							},
							"subject": map[string]any{},
						}, trailRecords[0].Fields["trail"])
					}
				})
			})
		}
	})

	t.Run("with nil options", func(t *testing.T) {
		opaModule := core.MustNewOPAModuleConfig([]core.Module{
			{
				Name: "example.rego",
				Content: `package policies
			responsepolicy [body] {
				body := input.response.body
		}`,
			},
		})

		sdk, err := NewWithConfig(context.Background(), opaModule, core.RondConfig{
			RequestFlow:  core.RequestFlow{PolicyName: "todo"},
			ResponseFlow: core.ResponseFlow{PolicyName: "responsepolicy"},
		}, nil)
		require.NoError(t, err)

		result, err := sdk.EvaluateResponsePolicy(context.Background(), core.Input{
			Response: core.InputResponse{
				Body: map[string]string{"foo": "bar"},
			},
		}, nil)
		require.NoError(t, err)
		require.Equal(t, `{"foo":"bar"}`, string(result))
	})
}

func BenchmarkEvaluateRequest(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")

	mongoClient := &mocks.MongoClientMock{
		FindOneResult: map[string]any{
			"_id":      "project123",
			"tenantId": "tenantId",
		},
		FindOneExpectation: func(collectionName string, query interface{}) {
			b.StopTimer()
			require.Equal(b, "projects", collectionName)

			require.Equal(b, query, map[string]any{
				"$expr": map[string]any{
					"$eq": []any{
						"$_id",
						map[string]any{
							"$toObjectId": "project123",
						},
					},
				},
			})
			b.StartTimer()
		},
	}

	user := core.InputUser{
		ID: "user1",
		Bindings: []types.Binding{
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
				BindingID: "binding-company-owner",
				Subjects:  []string{"user1"},
				Roles:     []string{"company_owner"},
				Resource: &types.Resource{
					ResourceType: "company",
					ResourceID:   "myCompany",
				},
				CRUDDocumentState: "PUBLIC",
			},
		},
		Roles: []types.Role{
			{
				RoleID:            "company_owner",
				Permissions:       []string{"console.company.project.view", "console.company.project.environment.view"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "admin",
				Permissions:       []string{"console.project.view", "console.project.environment.view", "permission2", "foobar"},
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

	config := core.RondConfig{
		RequestFlow: core.RequestFlow{
			PolicyName: "allow_view_project",
		},
	}

	evaluator, err := NewWithConfig(context.Background(), moduleConfig, config, &Options{
		EvaluatorOptions: &EvaluatorOptions{
			MongoClient: mongoClient,
		},
	})
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		headers := http.Header{}
		headers.Set("my-header", "value")

		rondInput := getFakeInput(b, core.InputRequest{
			Path:    "/projects/project123",
			Headers: headers,
			Method:  http.MethodGet,
			PathParams: map[string]string{
				"projectId": "project123",
			},
		}, "", user, nil)

		b.StartTimer()
		policyResult, err := evaluator.EvaluateRequestPolicy(context.Background(), rondInput, nil)
		b.StopTimer()

		require.NoError(b, err)
		require.Equal(b, PolicyResult{
			QueryToProxy: nil,
			Allowed:      true,
		}, policyResult)
	}
}

func BenchmarkEvaluateRequestWithQueryGeneration(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")

	config := core.RondConfig{
		RequestFlow: core.RequestFlow{
			PolicyName:    "filter_projects",
			GenerateQuery: true,
		},
	}

	user := core.InputUser{
		ID: "user1",
		Bindings: []types.Binding{
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
				BindingID: "binding-company-owner",
				Subjects:  []string{"user1"},
				Roles:     []string{"company_owner"},
				Resource: &types.Resource{
					ResourceType: "company",
					ResourceID:   "myCompany",
				},
				CRUDDocumentState: "PUBLIC",
			},
		},
		Roles: []types.Role{
			{
				RoleID:            "company_owner",
				Permissions:       []string{"console.company.project.view", "console.company.project.environment.view"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "admin",
				Permissions:       []string{"console.project.view", "console.project.environment.view", "permission2", "foobar"},
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

	evaluator, err := NewWithConfig(context.Background(), moduleConfig, config, &Options{
		EvaluatorOptions: &EvaluatorOptions{
			MongoClient: mocks.MongoClientMock{},
		},
	})
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		headers := http.Header{}
		headers.Set("my-header", "value")

		rondInput := getFakeInput(b, core.InputRequest{
			Path:       "/projects/",
			Headers:    headers,
			Method:     http.MethodGet,
			PathParams: map[string]string{},
		}, "", user, nil)

		b.StartTimer()
		policyResult, err := evaluator.EvaluateRequestPolicy(context.Background(), rondInput, nil)
		b.StopTimer()

		require.NoError(b, err)
		require.Equal(b, PolicyResult{
			QueryToProxy: []byte(`{"$or":[{"$and":[{"tenantId":{"$eq":"myCompany"}}]},{"$and":[{"_id":{"$eq":"project123"}}]}]}`),
			Allowed:      true,
		}, policyResult)
	}
}

func BenchmarkEvaluateResponse(b *testing.B) {
	moduleConfig, err := core.LoadRegoModule("../mocks/bench-policies")
	require.NoError(b, err, "Unexpected error")

	config := core.RondConfig{
		RequestFlow: core.RequestFlow{
			PolicyName: "allow_all",
		},
		ResponseFlow: core.ResponseFlow{
			PolicyName: "projection_project_environments",
		},
	}

	user := core.InputUser{
		ID: "user1",
		Bindings: []types.Binding{{
			BindingID: "binding-env",
			Subjects:  []string{"user1"},
			Roles:     []string{"env-reader"},
			Resource: &types.Resource{
				ResourceType: "environment",
				ResourceID:   "projectWithEnv:my-preprod-env",
			},
			CRUDDocumentState: "PUBLIC",
		},
			{
				BindingID: "binding-projectWithEnv-project-reader",
				Subjects:  []string{"user1"},
				Roles:     []string{"project-reader"},
				Resource: &types.Resource{
					ResourceType: "project",
					ResourceID:   "projectWithEnv",
				},
				CRUDDocumentState: "PUBLIC",
			},
		},
		Roles: []types.Role{
			{
				RoleID:            "env-reader",
				Permissions:       []string{"console.environment.view"},
				CRUDDocumentState: "PUBLIC",
			},
			{
				RoleID:            "project-reader",
				Permissions:       []string{"console.project.view"},
				CRUDDocumentState: "PUBLIC",
			},
		},
	}

	evaluator, err := NewWithConfig(context.Background(), moduleConfig, config, &Options{
		EvaluatorOptions: &EvaluatorOptions{
			MongoClient: &mocks.MongoClientMock{},
		},
	})
	require.NoError(b, err)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		headers := http.Header{}
		headers.Set("my-header", "value")

		decodedBody := map[string]any{
			"_id":       "projectWithEnv",
			"projectId": "my-project",
			"tenantId":  "my-tenant",
			"environments": []map[string]any{
				{
					"envId": "my-dev-env",
				},
				{
					"envId": "my-preprod-env",
				},
				{
					"envId": "my-prod-env",
				},
			},
		}

		rondInput := getFakeInput(b, core.InputRequest{
			Path:    "/projects/projectWithEnv",
			Headers: headers,
			Method:  http.MethodGet,
			PathParams: map[string]string{
				"projectId": "projectWithEnv",
			},
		}, "", user, decodedBody)

		b.StartTimer()
		policyResult, err := evaluator.EvaluateResponsePolicy(context.Background(), rondInput, nil)
		b.StopTimer()

		require.NoError(b, err)

		expectedProject := map[string]any{
			"_id":       "projectWithEnv",
			"projectId": "my-project",
			"tenantId":  "my-tenant",
			"environments": []interface{}{
				map[string]any{
					"envId": "my-preprod-env",
				},
			},
		}

		actualProject := map[string]any{}
		err = json.Unmarshal(policyResult, &actualProject)
		require.NoError(b, err)

		require.Equal(b, expectedProject, actualProject)
	}
}

func getOASSdk(t require.TestingT, options *sdkOptions) OASEvaluatorFinder {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	logger := logging.NewNoOpLogger()
	if options.logger != nil {
		logger = options.logger
	}

	if options == nil {
		options = &sdkOptions{}
	}

	var oasFilePath = "../mocks/simplifiedMock.json"
	if options.oasFilePath != "" {
		oasFilePath = options.oasFilePath
	}

	openAPISpec, err := openapi.LoadOASFile(oasFilePath)
	require.NoError(t, err)
	content := `package policies
		todo { true }`
	if options.opaModuleContent != "" {
		content = options.opaModuleContent
	}
	opaModule := core.MustNewOPAModuleConfig([]core.Module{
		{Name: "example.rego", Content: content},
	})

	sdk, err := NewFromOAS(context.Background(), opaModule, openAPISpec, &Options{
		Metrics: options.metrics,
		EvaluatorOptions: &EvaluatorOptions{
			EnablePrintStatements: true,
			MongoClient:           options.mongoClient,
			EnableAuditTracing:    options.enableAudit,
		},
		Logger: logger,
	})
	require.NoError(t, err)

	return sdk
}
