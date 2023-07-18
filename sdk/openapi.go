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
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/metrics"
	"github.com/rond-authz/rond/openapi"

	"github.com/uptrace/bunrouter"
)

type oasImpl struct {
	oas       *openapi.OpenAPISpec
	oasRouter *bunrouter.CompatRouter

	opaModuleConfig         *core.OPAModuleConfig
	partialResultEvaluators core.PartialResultsEvaluators
	opaEvaluatorOptions     *core.OPAEvaluatorOptions
	metrics                 *metrics.Metrics
}

func (r oasImpl) FindEvaluator(logger logging.Logger, method, path string) (Evaluator, error) {
	permission, routerInfo, err := r.oas.FindPermission(r.oasRouter, path, method)
	if err != nil {
		return nil, err
	}
	return evaluator{
		rondConfig:              permission,
		logger:                  logger,
		opaModuleConfig:         r.opaModuleConfig,
		partialResultEvaluators: r.partialResultEvaluators,

		opaEvaluatorOptions: r.opaEvaluatorOptions,
		policyEvaluationOptions: &core.PolicyEvaluationOptions{
			Metrics: r.metrics,
			AdditionalLogFields: map[string]string{
				"matchedPath":   routerInfo.MatchedPath,
				"requestedPath": routerInfo.RequestedPath,
				"method":        routerInfo.Method,
			},
		},
	}, err
}

type OASEvaluatorFinder interface {
	FindEvaluator(logger logging.Logger, method, path string) (Evaluator, error)
}
