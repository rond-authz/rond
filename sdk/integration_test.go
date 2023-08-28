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

package sdk_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"

	"github.com/stretchr/testify/require"
)

func TestUsageNewWithConfig(t *testing.T) {
	opaModuleConfig, err := core.LoadRegoModule("../mocks/rego-policies")
	require.NoError(t, err, "unexpected error")

	ctx := context.Background()

	rondConfig := core.RondConfig{
		RequestFlow: core.RequestFlow{
			PolicyName: "foobar",
		},
	}

	evaluator, err := sdk.NewWithConfig(ctx, opaModuleConfig, rondConfig, nil)
	require.NoError(t, err)

	input := core.Input{}
	result, err := evaluator.EvaluateRequestPolicy(ctx, input, nil)
	require.NoError(t, err)
	require.Equal(t, result, sdk.PolicyResult{
		Allowed:      true,
		QueryToProxy: []byte(""),
	})
}

func TestUsageNewWithConfigWithMongo(t *testing.T) {
	opaModuleConfig, err := core.LoadRegoModule("../mocks/rego-policies-with-mongo-builtins")
	require.NoError(t, err, "unexpected error")

	ctx := context.Background()

	rondConfig := core.RondConfig{
		RequestFlow: core.RequestFlow{
			PolicyName: "foobar",
		},
	}

	evaluator, err := sdk.NewWithConfig(ctx, opaModuleConfig, rondConfig, &sdk.Options{
		EvaluatorOptions: &sdk.EvaluatorOptions{
			MongoClient: mocks.MongoClientMock{},
		},
	})
	require.NoError(t, err)

	input := core.Input{}

	result, err := evaluator.EvaluateRequestPolicy(ctx, input, nil)
	require.NoError(t, err)
	require.Equal(t, result, sdk.PolicyResult{
		Allowed:      true,
		QueryToProxy: []byte(""),
	})
}

func TestUsageNewFromOas(t *testing.T) {
	opaModuleConfig, err := core.LoadRegoModule("../mocks/rego-policies")
	require.NoError(t, err, "unexpected error")
	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.NoError(t, err)

	ctx := context.Background()
	logger := logging.NewNoOpLogger()

	oasFinder, err := sdk.NewFromOAS(ctx, opaModuleConfig, openAPISpec, nil)
	require.NoError(t, err)

	evaluator, err := oasFinder.FindEvaluator(http.MethodGet, "/users/")
	require.NoError(t, err)

	input := core.Input{}
	result, err := evaluator.EvaluateRequestPolicy(ctx, input, &sdk.EvaluateOptions{
		Logger: logger,
	})
	require.NoError(t, err)
	require.Equal(t, result, sdk.PolicyResult{
		Allowed:      true,
		QueryToProxy: []byte(""),
	})
}

func TestUsageNewFromOasWithMongo(t *testing.T) {
	opaModuleConfig, err := core.LoadRegoModule("../mocks/rego-policies-with-mongo-builtins")
	require.NoError(t, err, "unexpected error")
	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.NoError(t, err)

	ctx := context.Background()
	logger := logging.NewNoOpLogger()

	oasFinder, err := sdk.NewFromOAS(ctx, opaModuleConfig, openAPISpec, &sdk.Options{
		EvaluatorOptions: &sdk.EvaluatorOptions{
			MongoClient: mocks.MongoClientMock{},
		},
	})
	require.NoError(t, err)

	evaluator, err := oasFinder.FindEvaluator(http.MethodGet, "/users/")
	require.NoError(t, err)

	input := core.Input{}
	result, err := evaluator.EvaluateRequestPolicy(ctx, input, &sdk.EvaluateOptions{
		Logger: logger,
	})
	require.NoError(t, err)
	require.Equal(t, result, sdk.PolicyResult{
		Allowed:      true,
		QueryToProxy: []byte(""),
	})
}
