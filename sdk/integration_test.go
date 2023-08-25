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
	result, err := evaluator.EvaluateRequestPolicy(ctx, input)
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
		EvaluatorOptions: &core.OPAEvaluatorOptions{
			MongoClient: mocks.MongoClientMock{},
		},
	})
	require.NoError(t, err)

	input := core.Input{}

	result, err := evaluator.EvaluateRequestPolicy(ctx, input)
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

	evaluator, err := oasFinder.FindEvaluator(logger, http.MethodGet, "/users/")
	require.NoError(t, err)

	input := core.Input{}
	result, err := evaluator.EvaluateRequestPolicy(ctx, input)
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
		EvaluatorOptions: &core.OPAEvaluatorOptions{
			MongoClient: mocks.MongoClientMock{},
		},
	})
	require.NoError(t, err)

	evaluator, err := oasFinder.FindEvaluator(logger, http.MethodGet, "/users/")
	require.NoError(t, err)

	input := core.Input{}
	result, err := evaluator.EvaluateRequestPolicy(ctx, input)
	require.NoError(t, err)
	require.Equal(t, result, sdk.PolicyResult{
		Allowed:      true,
		QueryToProxy: []byte(""),
	})
}