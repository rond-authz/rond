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

package openapi

import (
	"context"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logging"

	"github.com/stretchr/testify/require"
)

func TestCreatePolicyEvaluators(t *testing.T) {
	t.Run("with simplified mock", func(t *testing.T) {
		logger := logging.NewNoOpLogger()
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
		logger := logging.NewNoOpLogger()
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
		logger := logging.NewNoOpLogger()
		ctx := context.Background()

		_, err := SetupEvaluators(ctx, logger, nil, nil, nil)
		require.EqualError(t, err, "oas must not be nil")
	})

	t.Run("with complete oas mock", func(t *testing.T) {
		logger := logging.NewNoOpLogger()
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
