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
	"fmt"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/openapi"

	"github.com/prometheus/client_golang/prometheus"
)

type Options struct {
	Registry         *prometheus.Registry
	EvaluatorOptions *core.OPAEvaluatorOptions
	Logger           logging.Logger
}

func NewFromOAS(ctx context.Context, opaModuleConfig *core.OPAModuleConfig, oas *openapi.OpenAPISpec, options *Options) (OASEvaluatorFinder, error) {
	if opaModuleConfig == nil {
		return nil, fmt.Errorf("OPAModuleConfig must not be nil")
	}

	if options == nil {
		options = &Options{}
	}

	logger := options.Logger
	if logger == nil {
		logger = logging.NewNoOpLogger()
	}

	var evaluatorOptions *core.OPAEvaluatorOptions
	if options.EvaluatorOptions != nil {
		evaluatorOptions = options.EvaluatorOptions
	}
	metrics := setupMetrics(options.Registry)

	evaluator, err := openapi.SetupEvaluators(ctx, logger, oas, opaModuleConfig, evaluatorOptions)
	if err != nil {
		return nil, err
	}

	logger.WithField("policiesLength", len(evaluator)).Debug("policies evaluators partial results computed")

	oasRouter, err := oas.PrepareOASRouter()
	if err != nil {
		return nil, fmt.Errorf("invalid OAS configuration: %s", err)
	}

	return oasImpl{
		oas:       oas,
		oasRouter: oasRouter,

		opaModuleConfig:         opaModuleConfig,
		partialResultEvaluators: evaluator,
		opaEvaluatorOptions:     evaluatorOptions,
		metrics:                 metrics,
	}, nil
}

func NewWithConfig(ctx context.Context, opaModuleConfig *core.OPAModuleConfig, rondConfig core.RondConfig, options *Options) (Evaluator, error) {
	if options == nil {
		options = &Options{}
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.NewNoOpLogger()
	}

	policyEvaluators := core.PartialResultsEvaluators{}
	if err := policyEvaluators.AddFromConfig(ctx, logger, opaModuleConfig, &rondConfig, options.EvaluatorOptions); err != nil {
		return nil, err
	}
	metrics := setupMetrics(options.Registry)

	return evaluator{
		rondConfig:              rondConfig,
		logger:                  logger,
		opaModuleConfig:         opaModuleConfig,
		partialResultEvaluators: policyEvaluators,

		opaEvaluatorOptions: options.EvaluatorOptions,
		policyEvaluationOptions: &core.PolicyEvaluationOptions{
			Metrics: metrics,
		},
	}, nil
}

func setupMetrics(registry *prometheus.Registry) *metrics.Metrics {
	m := metrics.SetupMetrics("rond")
	if registry != nil {
		m.MustRegister(registry)
	}
	return &m
}
