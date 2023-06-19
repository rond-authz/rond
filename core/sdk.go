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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bunrouter"
)

type PolicyResult struct {
	QueryToProxy []byte
	Allowed      bool
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Does not use outside this repository until it is not ready.
type SDK interface {
	// Warning: this method will be removed in the near future. Do not use it outside Rond.
	Metrics() metrics.Metrics

	FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error)
	EvaluatorFromConfig(logger *logrus.Entry, config openapi.RondConfig) SDKEvaluator
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Do not use outside this repository until it is not ready.
type SDKEvaluator interface {
	Config() openapi.RondConfig
	PartialResultsEvaluators() PartialResultsEvaluators

	EvaluateRequestPolicy(req RondInput, userInfo types.User) (PolicyResult, error)
	// EvaluateResponsePolicy(req *http.Request, userInfo types.User, permission *openapi.RondConfig) (PolicyResult, error)
}

type evaluator struct {
	rond       rondImpl
	logger     *logrus.Entry
	rondConfig openapi.RondConfig
}

func (e evaluator) Config() openapi.RondConfig {
	return e.rondConfig
}

func (e evaluator) PartialResultsEvaluators() PartialResultsEvaluators {
	return e.rond.evaluator
}

func (e evaluator) EvaluateRequestPolicy(req RondInput, userInfo types.User) (PolicyResult, error) {
	rondConfig := e.rondConfig
	requestContext := req.Context()

	input, err := req.FromRequestInfo(userInfo, nil)
	if err != nil {
		return PolicyResult{}, err
	}

	regoInput, err := CreateRegoQueryInput(e.logger, input, RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return PolicyResult{}, nil
	}

	var evaluatorAllowPolicy *OPAEvaluator
	if !rondConfig.RequestFlow.GenerateQuery {
		evaluatorAllowPolicy, err = e.rond.evaluator.GetEvaluatorFromPolicy(requestContext, rondConfig.RequestFlow.PolicyName, regoInput, e.rond.evaluatorOptions)
		if err != nil {
			return PolicyResult{}, nil
		}
	} else {
		evaluatorAllowPolicy, err = CreateQueryEvaluator(requestContext, e.logger, req.OriginalRequest(), rondConfig.RequestFlow.PolicyName, regoInput, nil, e.rond.evaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(e.logger, &rondConfig)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && utils.HasApplicationJSONContentType(req.OriginalRequest().Header) {
			return PolicyResult{}, err
		}

		e.logger.WithField("error", logrus.Fields{
			"policyName": rondConfig.RequestFlow.PolicyName,
			"message":    err.Error(),
		}).Error("RBAC policy evaluation failed")
		return PolicyResult{}, err
	}

	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	return PolicyResult{
		Allowed:      true,
		QueryToProxy: queryToProxy,
	}, nil
}

type rondImpl struct {
	evaluator        PartialResultsEvaluators
	evaluatorOptions *EvaluatorOptions
	oasRouter        *bunrouter.CompatRouter
	oas              *openapi.OpenAPISpec

	metrics  metrics.Metrics
	registry *prometheus.Registry

	clientTypeHeaderKey string
}

func (r rondImpl) FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error) {
	permission, err := r.oas.FindPermission(r.oasRouter, path, method)
	return evaluator{
		rondConfig: permission,
		logger:     logger,
		rond:       r,
	}, err
}

func (r rondImpl) EvaluatorFromConfig(logger *logrus.Entry, config openapi.RondConfig) SDKEvaluator {
	return evaluator{
		rondConfig: config,
		logger:     logger,
		rond:       r,
	}
}

func (r rondImpl) Metrics() metrics.Metrics {
	return r.metrics
}

// The SDK is now into core because there are coupled function here which should use the SDK itself
// (which uses core, so it will result in a cyclic dependency). In the future, sdk should be in a
// specific package.
func NewSDK(
	ctx context.Context,
	logger *logrus.Entry,
	mongoClient types.IMongoClient,
	oas *openapi.OpenAPISpec,
	opaModuleConfig *OPAModuleConfig,
	evaluatorOptions *EvaluatorOptions,
	registry *prometheus.Registry,
	clientTypeHeaderKey string,
) (SDK, error) {
	evaluator, err := SetupEvaluators(ctx, logger, mongoClient, oas, opaModuleConfig, evaluatorOptions)
	if err != nil {
		return nil, err
	}

	logger.WithField("policiesLength", len(evaluator)).Debug("policies evaluators partial results computed")

	oasRouter, err := oas.PrepareOASRouter()
	if err != nil {
		return nil, fmt.Errorf("invalid OAS configuration: %s", err)
	}

	m := metrics.SetupMetrics("rond")
	if registry != nil {
		m.MustRegister(registry)
	}

	return rondImpl{
		evaluator:        evaluator,
		oasRouter:        oasRouter,
		evaluatorOptions: evaluatorOptions,
		oas:              oas,

		metrics:  m,
		registry: registry,

		clientTypeHeaderKey: clientTypeHeaderKey,
	}, nil
}

type sdkKey struct{}

func WithEvaluatorSKD(ctx context.Context, evaluator SDKEvaluator) context.Context {
	return context.WithValue(ctx, sdkKey{}, evaluator)
}

func GetEvaluatorSKD(ctx context.Context) (SDKEvaluator, error) {
	sdk, ok := ctx.Value(sdkKey{}).(SDKEvaluator)
	if !ok {
		return nil, fmt.Errorf("no SDKEvaluator found in request context")
	}

	return sdk, nil
}
