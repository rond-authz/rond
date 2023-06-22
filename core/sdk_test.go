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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestNewSDK(t *testing.T) {
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}

	t.Run("fails if oas is nil", func(t *testing.T) {
		sdk, err := NewSDK(context.Background(), logger, nil, nil, nil, nil, nil, "")
		require.ErrorContains(t, err, "oas must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("fails if opaModuleConfig is nil", func(t *testing.T) {
		sdk, err := NewSDK(context.Background(), logger, nil, openAPISpec, nil, nil, nil, "")
		require.ErrorContains(t, err, "OPAModuleConfig must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("fails if oas is invalid", func(t *testing.T) {
		oas, err := openapi.LoadOASFile("../mocks/invalidOASConfiguration.json")
		require.NoError(t, err)
		sdk, err := NewSDK(context.Background(), logger, nil, oas, opaModule, nil, nil, "")
		require.ErrorContains(t, err, "invalid OAS configuration:")
		require.Nil(t, sdk)
	})

	t.Run("creates sdk correctly", func(t *testing.T) {
		sdk, err := NewSDK(context.Background(), logger, nil, openAPISpec, opaModule, nil, nil, "")
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
	})

	t.Run("if registry is passed, setup metrics", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		sdk, err := NewSDK(context.Background(), logger, nil, openAPISpec, opaModule, nil, registry, "")
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
	})
}

func TestSDK(t *testing.T) {
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}
	registry := prometheus.NewRegistry()
	sdk, err := NewSDK(context.Background(), logger, nil, openAPISpec, opaModule, nil, registry, "")
	require.NoError(t, err)

	rond, ok := sdk.(rondImpl)
	require.True(t, ok, "rondImpl is not sdk")

	t.Run("metrics", func(t *testing.T) {
		require.Equal(t, rond.metrics, sdk.Metrics())
	})

	t.Run("FindEvaluator", func(t *testing.T) {
		t.Run("throws if path and method not found", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/not-existent/path")
			require.ErrorContains(t, err, "not found oas definition: GET /not-existent/path")
			require.Equal(t, evaluator{
				rondConfig: openapi.RondConfig{},
				logger:     logger,
				rond:       rond,
			}, actual)
		})

		t.Run("returns correct evaluator", func(t *testing.T) {
			actual, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			require.Equal(t, evaluator{
				rondConfig: openapi.RondConfig{
					RequestFlow: openapi.RequestFlow{
						PolicyName: "todo",
					},
				},
				logger: logger,
				rond:   rond,
			}, actual)

			t.Run("get permissions", func(t *testing.T) {
				require.Equal(t, openapi.RondConfig{
					RequestFlow: openapi.RequestFlow{
						PolicyName: "todo",
					},
				}, actual.Config())
			})

			t.Run("get partial evaluators", func(t *testing.T) {
				require.Equal(t, rond.evaluator, actual.PartialResultsEvaluators())
			})
		})
	})
}

func TestEvaluateRequestPolicy(t *testing.T) {
	// log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(logrus.New())

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.Nil(t, err)
	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		todo { true }`,
	}
	registry := prometheus.NewRegistry()
	sdk, err := NewSDK(context.Background(), logger, nil, openAPISpec, opaModule, nil, registry, "")
	require.NoError(t, err)

	clientTypeHeaderKey := "client-header-key"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rondInput := NewRondInput(req, clientTypeHeaderKey, nil, "")

	t.Run("throws without RondInput", func(t *testing.T) {
		evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
		require.NoError(t, err)

		_, err = evaluator.EvaluateRequestPolicy(nil, types.User{})
		require.EqualError(t, err, "RondInput cannot be empty")
	})

	t.Run("with empty user", func(t *testing.T) {
		evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
		require.NoError(t, err)

		actual, err := evaluator.EvaluateRequestPolicy(rondInput, types.User{})
		require.NoError(t, err)
		require.Equal(t, PolicyResult{
			Allowed: true,
		}, actual)
	})

	// t.Run("with RondInput empty returns error with path params", func(t *testing.T) {
	// 	evaluator := sdk.EvaluatorFromConfig(logger, rondConfig)

	// 	_, err := evaluator.EvaluateRequestPolicy(nil, types.User{})
	// 	require.EqualError(t, err, "RondInput cannot be empty")
	// })
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

		ctx = WithEvaluatorSKD(ctx, expectedEvaluator)

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
