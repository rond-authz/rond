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

package openapi

import (
	"context"
	"fmt"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logger"
)

func SetupEvaluators(ctx context.Context, logger logger.Logger, oas *OpenAPISpec, opaModuleConfig *core.OPAModuleConfig, options *core.OPAEvaluatorOptions) (core.PartialResultsEvaluators, error) {
	if oas == nil {
		return nil, fmt.Errorf("oas must not be nil")
	}

	policyEvaluators := core.PartialResultsEvaluators{}
	for path, OASContent := range oas.Paths {
		for verb, verbConfig := range OASContent {
			if verbConfig.PermissionV2 == nil {
				continue
			}

			logger.
				WithFields(map[string]any{
					"verb": verb,
					"path": path,
				}).
				Info("precomputing rego evaluators for API")

			if err := policyEvaluators.AddFromConfig(ctx, logger, opaModuleConfig, verbConfig.PermissionV2, options); err != nil {
				// allow policy is required, if missing assume the API has no valid x-rond configuration.
				continue
			}
		}
	}
	return policyEvaluators, nil
}
