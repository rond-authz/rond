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
	"fmt"
	"time"

	"github.com/rond-authz/rond/internal/metrics"
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
	FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error)
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Do not use outside this repository until it is not ready.
type SDKEvaluator interface {
	Config() openapi.RondConfig

	EvaluateRequestPolicy(ctx context.Context, req RondInput, userInfo types.User) (PolicyResult, error)
	EvaluateResponsePolicy(ctx context.Context, rondInput RondInput, userInfo types.User, decodedBody any) ([]byte, error)
}

type evaluator struct {
	rond       rondImpl
	logger     *logrus.Entry
	rondConfig openapi.RondConfig

	routeInfo openapi.RouterInfo
}

func (e evaluator) metrics() metrics.Metrics {
	return e.rond.metrics
}

func (e evaluator) partialResultEvaluators() PartialResultsEvaluators {
	return e.rond.partialResultEvaluators
}

func (e evaluator) Config() openapi.RondConfig {
	return e.rondConfig
}

func (e evaluator) EvaluateRequestPolicy(ctx context.Context, req RondInput, userInfo types.User) (PolicyResult, error) {
	if req == nil {
		return PolicyResult{}, fmt.Errorf("RondInput cannot be empty")
	}

	rondConfig := e.Config()

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
		evaluatorAllowPolicy, err = e.partialResultEvaluators().GetEvaluatorFromPolicy(ctx, rondConfig.RequestFlow.PolicyName, regoInput, e.rond.evaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	} else {
		evaluatorAllowPolicy, err = e.rond.opaModuleConfig.CreateQueryEvaluator(ctx, e.logger, rondConfig.RequestFlow.PolicyName, regoInput, e.rond.evaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	opaEvaluationTimeStart := time.Now()

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(e.logger, &rondConfig)

	policyName := rondConfig.RequestFlow.PolicyName
	opaEvaluationTime := time.Since(opaEvaluationTimeStart)
	e.metrics().PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": policyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	e.logger.WithFields(logrus.Fields{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 policyName,
		"partialEval":                rondConfig.RequestFlow.GenerateQuery,
		"allowed":                    err == nil,
		"matchedPath":                e.routeInfo.MatchedPath,
		"requestedPath":              e.routeInfo.RequestedPath,
		"method":                     e.routeInfo.Method,
	}).Debug("policy evaluation completed")
	if err != nil {
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

func (e evaluator) EvaluateResponsePolicy(ctx context.Context, rondInput RondInput, userInfo types.User, decodedBody any) ([]byte, error) {
	if rondInput == nil {
		return nil, fmt.Errorf("RondInput cannot be empty")
	}

	rondConfig := e.Config()

	input, err := rondInput.FromRequestInfo(userInfo, decodedBody)
	if err != nil {
		return nil, err
	}

	regoInput, err := CreateRegoQueryInput(e.logger, input, RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return nil, err
	}

	opaEvaluationTimeStart := time.Now()

	evaluator, err := e.partialResultEvaluators().GetEvaluatorFromPolicy(ctx, e.rondConfig.ResponseFlow.PolicyName, regoInput, e.rond.evaluatorOptions)

	policyName := rondConfig.ResponseFlow.PolicyName
	opaEvaluationTime := time.Since(opaEvaluationTimeStart)
	e.metrics().PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": policyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	e.logger.WithFields(logrus.Fields{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 policyName,
		"partialEval":                false,
		"allowed":                    err == nil,
		"matchedPath":                e.routeInfo.MatchedPath,
		"requestedPath":              e.routeInfo.RequestedPath,
		"method":                     e.routeInfo.Method,
	}).Debug("policy evaluation completed")

	if err != nil {
		return nil, err
	}

	bodyToProxy, err := evaluator.Evaluate(e.logger)
	if err != nil {
		return nil, err
	}

	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		return nil, err
	}

	return marshalledBody, nil
}

type rondImpl struct {
	partialResultEvaluators PartialResultsEvaluators
	evaluatorOptions        *EvaluatorOptions
	oasRouter               *bunrouter.CompatRouter
	oas                     *openapi.OpenAPISpec
	opaModuleConfig         *OPAModuleConfig

	metrics metrics.Metrics

	clientTypeHeaderKey string
}

func (r rondImpl) FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error) {
	permission, routerInfo, err := r.oas.FindPermission(r.oasRouter, path, method)
	return evaluator{
		rondConfig: permission,
		logger:     logger,
		rond:       r,

		routeInfo: routerInfo,
	}, err
}

// The SDK is now into core because there are coupled function here which should use the SDK itself
// (which uses core, so it will result in a cyclic dependency). In the future, sdk should be in a
// specific package.
func NewSDK(
	ctx context.Context,
	logger *logrus.Entry,
	oas *openapi.OpenAPISpec,
	opaModuleConfig *OPAModuleConfig,
	evaluatorOptions *EvaluatorOptions,
	registry *prometheus.Registry,
	clientTypeHeaderKey string,
) (SDK, error) {
	evaluator, err := SetupEvaluators(ctx, logger, oas, opaModuleConfig, evaluatorOptions)
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
		partialResultEvaluators: evaluator,
		oasRouter:               oasRouter,
		evaluatorOptions:        evaluatorOptions,
		oas:                     oas,
		opaModuleConfig:         opaModuleConfig,

		metrics: m,

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
