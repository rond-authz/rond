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
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/audit"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/metrics"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"
)

type AuditLabels = audit.Labels

type AuditEvaluatorOptions struct {
	MongoDBClient       types.MongoClient
	StorageMode         []string
	AuditCollectionName string
	AuditConfig         audit.Config
}

type EvaluatorOptions struct {
	MongoClient           custom_builtins.IMongoClient
	EnablePrintStatements bool
	EnableAuditTracing    bool
	AuditTracingOptions   AuditEvaluatorOptions
}

func (e EvaluatorOptions) opaEvaluatorOptions(logger logging.Logger) *core.OPAEvaluatorOptions {
	return &core.OPAEvaluatorOptions{
		Logger:                logger,
		MongoClient:           e.MongoClient,
		EnablePrintStatements: e.EnablePrintStatements,
	}
}

type Options struct {
	EvaluatorOptions *EvaluatorOptions
	Metrics          *metrics.Metrics
	Logger           logging.Logger
	AuditLabels      AuditLabels
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

	evaluatorOptions := options.EvaluatorOptions
	if evaluatorOptions == nil {
		evaluatorOptions = &EvaluatorOptions{}
	}

	evaluator, err := openapi.SetupEvaluators(ctx, logger, oas, opaModuleConfig, evaluatorOptions.opaEvaluatorOptions(logger))
	if err != nil {
		return nil, err
	}

	logger.WithField("policiesLength", len(evaluator)).Debug("policies evaluators partial results computed")

	oasRouter, err := oas.PrepareOASRouter()
	if err != nil {
		return nil, fmt.Errorf("invalid OAS configuration: %s", err)
	}

	auditAgent := buildAuditAgent(options, logger)

	return oasImpl{
		oas:       oas,
		oasRouter: oasRouter,

		opaModuleConfig:         opaModuleConfig,
		partialResultEvaluators: evaluator,
		evaluatorOptions:        evaluatorOptions,
		metrics:                 options.Metrics,
		auditAgentPool:          auditAgent,
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

	evaluatorOptions := options.EvaluatorOptions
	if evaluatorOptions == nil {
		evaluatorOptions = &EvaluatorOptions{}
	}

	policyEvaluators := core.PartialResultsEvaluators{}
	if err := policyEvaluators.AddFromConfig(ctx, logger, opaModuleConfig, &rondConfig, evaluatorOptions.opaEvaluatorOptions(logger)); err != nil {
		return nil, err
	}

	auditAgent := buildAuditAgent(options, logger)

	return evaluator{
		rondConfig:              rondConfig,
		opaModuleConfig:         opaModuleConfig,
		partialResultEvaluators: policyEvaluators,

		evaluatorOptions: evaluatorOptions,
		policyEvaluationOptions: &core.PolicyEvaluationOptions{
			Metrics: options.Metrics,
		},
		auditAgentPool: auditAgent,
	}, nil
}
