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
	"encoding/json"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/logging"
)

type PolicyResult struct {
	QueryToProxy []byte
	Allowed      bool
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Do not use outside this repository until it is ready.
type Evaluator interface {
	// retrieve the RondConfig used to generate the evaluator
	Config() core.RondConfig

	// EvaluateResponsePolicy evaluate request policy. In the response, it is specified if the
	// request is allowed and the request query (if filter generation is requested)
	EvaluateRequestPolicy(ctx context.Context, input core.Input, options *EvaluateOptions) (PolicyResult, error)
	// EvaluateResponsePolicy evaluate response policy. The response is the response
	// value returned by the policy.
	EvaluateResponsePolicy(ctx context.Context, input core.Input, options *EvaluateOptions) ([]byte, error)
}

type evaluator struct {
	rondConfig              core.RondConfig
	opaModuleConfig         *core.OPAModuleConfig
	partialResultEvaluators core.PartialResultsEvaluators

	evaluatorOptions        *EvaluatorOptions
	policyEvaluationOptions *core.PolicyEvaluationOptions
}

func (e evaluator) Config() core.RondConfig {
	return e.rondConfig
}

type EvaluateOptions struct {
	Logger logging.Logger
}

func (e EvaluateOptions) GetLogger() logging.Logger {
	if e.Logger == nil {
		return logging.NewNoOpLogger()
	}
	return e.Logger
}

func (e evaluator) EvaluateRequestPolicy(ctx context.Context, rondInput core.Input, options *EvaluateOptions) (PolicyResult, error) {
	rondConfig := e.Config()
	if options == nil {
		options = &EvaluateOptions{}
	}
	logger := options.GetLogger()

	regoInput, err := core.CreateRegoQueryInput(logger, rondInput, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return PolicyResult{}, nil
	}

	opaEvaluatorOptions := e.evaluatorOptions.opaEvaluatorOptions(logger)

	var evaluatorAllowPolicy *core.OPAEvaluator
	if !rondConfig.RequestFlow.GenerateQuery {
		evaluatorAllowPolicy, err = e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, rondConfig.RequestFlow.PolicyName, regoInput, opaEvaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	} else {
		evaluatorAllowPolicy, err = e.opaModuleConfig.CreateQueryEvaluator(ctx, logger, rondConfig.RequestFlow.PolicyName, regoInput, opaEvaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	// TODO: here if the evaluation result false, it is returned an error. This interface
	// for the sdk should be improved, since it should use the PolicyResult and return error
	// only if there is some error in policy evaluation.
	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(logger, e.policyEvaluationOptions)

	if err != nil {
		logger.WithField("error", map[string]any{
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

func (e evaluator) EvaluateResponsePolicy(ctx context.Context, rondInput core.Input, options *EvaluateOptions) ([]byte, error) {
	rondConfig := e.Config()
	if options == nil {
		options = &EvaluateOptions{}
	}
	logger := options.GetLogger()

	regoInput, err := core.CreateRegoQueryInput(logger, rondInput, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return nil, err
	}

	opaEvaluatorOptions := e.evaluatorOptions.opaEvaluatorOptions(logger)

	evaluator, err := e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, e.rondConfig.ResponseFlow.PolicyName, regoInput, opaEvaluatorOptions)
	if err != nil {
		return nil, err
	}

	bodyToProxy, err := evaluator.Evaluate(logger, e.policyEvaluationOptions)
	if err != nil {
		return nil, err
	}

	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		return nil, err
	}

	return marshalledBody, nil
}
