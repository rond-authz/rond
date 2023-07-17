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
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logger"
	"github.com/rond-authz/rond/openapi"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestOasSDK(t *testing.T) {
	logger := logger.NewNullLogger()

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}
	registry := prometheus.NewRegistry()
	sdk, err := NewFromOAS(context.Background(), opaModule, openAPISpec, &Options{
		Registry: registry,
		Logger:   logger,
	})
	require.NoError(t, err)

	oas, ok := sdk.(oasImpl)
	require.True(t, ok, "oasImpl is not sdk")

	t.Run("FindEvaluator", func(t *testing.T) {
		t.Run("throws if path and method not found", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/not-existent/path")
			require.ErrorContains(t, err, "not found oas definition: GET /not-existent/path")
			require.Nil(t, actual)
		})

		t.Run("returns correct evaluator", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			evaluatorOptions := &core.PolicyEvaluationOptions{
				Metrics: oas.metrics,
				AdditionalLogFields: map[string]string{
					"matchedPath":   "/users/",
					"requestedPath": "/users/",
					"method":        http.MethodGet,
				},
			}
			require.Equal(t, evaluator{
				rondConfig: core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName: "todo",
					},
				},
				opaModuleConfig:         opaModule,
				partialResultEvaluators: oas.partialResultEvaluators,
				logger:                  logger,
				policyEvaluationOptions: evaluatorOptions,
			}, actual)

			t.Run("get permissions", func(t *testing.T) {
				require.Equal(t, core.RondConfig{
					RequestFlow: core.RequestFlow{
						PolicyName: "todo",
					},
				}, actual.Config())
			})
		})
	})
}
