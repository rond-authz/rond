package openapi

import (
	"context"
	"fmt"

	"github.com/rond-authz/rond/core"

	"github.com/sirupsen/logrus"
)

func SetupEvaluators(ctx context.Context, logger *logrus.Entry, oas *OpenAPISpec, opaModuleConfig *core.OPAModuleConfig, options *core.OPAEvaluatorOptions) (core.PartialResultsEvaluators, error) {
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
				WithFields(logrus.Fields{
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
