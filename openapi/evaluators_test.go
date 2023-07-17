package openapi

import (
	"context"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logger"

	"github.com/stretchr/testify/require"
)

func TestCreatePolicyEvaluators(t *testing.T) {
	t.Run("with simplified mock", func(t *testing.T) {
		logger := logger.NewNullLogger()
		ctx := context.Background()

		opaModuleDirectory := "../mocks/rego-policies"
		loadOptions := LoadOptions{
			APIPermissionsFilePath: "../mocks/simplifiedMock.json",
		}
		openApiSpec, err := LoadOASFromFileOrNetwork(logger, loadOptions)
		require.NoError(t, err, "unexpected error")

		opaModuleConfig, err := core.LoadRegoModule(opaModuleDirectory)
		require.NoError(t, err, "unexpected error")

		policyEvals, err := SetupEvaluators(ctx, logger, openApiSpec, opaModuleConfig, nil)
		require.NoError(t, err, "unexpected error creating evaluators")
		require.Len(t, policyEvals, 4, "unexpected length")
	})

	t.Run("with complete oas mock", func(t *testing.T) {
		logger := logger.NewNullLogger()
		ctx := context.Background()

		opaModulesDirectory := "../mocks/rego-policies"

		loadOptions := LoadOptions{
			APIPermissionsFilePath: "../mocks/pathsConfigAllInclusive.json",
		}
		openApiSpec, err := LoadOASFromFileOrNetwork(logger, loadOptions)
		require.NoError(t, err, "unexpected error")

		opaModuleConfig, err := core.LoadRegoModule(opaModulesDirectory)
		require.NoError(t, err, "unexpected error")

		policyEvals, err := SetupEvaluators(ctx, logger, openApiSpec, opaModuleConfig, nil)
		require.NoError(t, err, "unexpected error creating evaluators")
		require.Len(t, policyEvals, 4, "unexpected length")
	})

	t.Run("with oas nil", func(t *testing.T) {
		logger := logger.NewNullLogger()
		ctx := context.Background()

		_, err := SetupEvaluators(ctx, logger, nil, nil, nil)
		require.EqualError(t, err, "oas must not be nil")
	})

	t.Run("with complete oas mock", func(t *testing.T) {
		logger := logger.NewNullLogger()
		ctx := context.Background()

		opaModulesDirectory := "../mocks/rego-policies"

		openApiSpec := &OpenAPISpec{
			Paths: OpenAPIPaths{
				"/invalid-path": PathVerbs{
					"GET": VerbConfig{
						PermissionV2: &core.RondConfig{},
					},
				},
				"/path": PathVerbs{
					"GET": VerbConfig{
						PermissionV2: &core.RondConfig{
							RequestFlow: core.RequestFlow{
								PolicyName: "allow",
							},
						},
					},
				},
			},
		}

		opaModuleConfig, err := core.LoadRegoModule(opaModulesDirectory)
		require.NoError(t, err, "unexpected error")

		policyEvals, err := SetupEvaluators(ctx, logger, openApiSpec, opaModuleConfig, nil)
		require.NoError(t, err, "unexpected error creating evaluators")
		require.Len(t, policyEvals, 1, "unexpected length")
	})
}
