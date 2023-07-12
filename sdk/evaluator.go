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
	"fmt"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus"
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
	EvaluateRequestPolicy(ctx context.Context, input core.RondInput, userInfo types.User) (PolicyResult, error)
	// EvaluateResponsePolicy evaluate response policy, take as input the decodedBody body from response
	// (unmarshalled) and it is usable as `input.response.body` in the policy. The response is the response
	// value returned by the policy.
	EvaluateResponsePolicy(ctx context.Context, input core.RondInput, userInfo types.User, decodedBody any) ([]byte, error)
}

type evaluator struct {
	logger                  *logrus.Entry
	rondConfig              core.RondConfig
	opaModuleConfig         *core.OPAModuleConfig
	partialResultEvaluators core.PartialResultsEvaluators

	opaEvaluatorOptions     *core.OPAEvaluatorOptions
	policyEvaluationOptions *core.PolicyEvaluationOptions
}

func (e evaluator) Config() core.RondConfig {
	return e.rondConfig
}

func (e evaluator) EvaluateRequestPolicy(ctx context.Context, req core.RondInput, userInfo types.User) (PolicyResult, error) {
	if req == nil {
		return PolicyResult{}, fmt.Errorf("RondInput cannot be empty")
	}

	rondConfig := e.Config()

	input, err := req.Input(userInfo, nil)
	if err != nil {
		return PolicyResult{}, err
	}

	regoInput, err := core.CreateRegoQueryInput(e.logger, input, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return PolicyResult{}, nil
	}

	var evaluatorAllowPolicy *core.OPAEvaluator
	if !rondConfig.RequestFlow.GenerateQuery {
		evaluatorAllowPolicy, err = e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, rondConfig.RequestFlow.PolicyName, regoInput, e.opaEvaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	} else {
		evaluatorAllowPolicy, err = e.opaModuleConfig.CreateQueryEvaluator(ctx, e.logger, rondConfig.RequestFlow.PolicyName, regoInput, e.opaEvaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(e.logger, &rondConfig, e.policyEvaluationOptions)

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

func (e evaluator) EvaluateResponsePolicy(ctx context.Context, rondInput core.RondInput, userInfo types.User, decodedBody any) ([]byte, error) {
	if rondInput == nil {
		return nil, fmt.Errorf("RondInput cannot be empty")
	}

	rondConfig := e.Config()

	input, err := rondInput.Input(userInfo, decodedBody)
	if err != nil {
		return nil, err
	}

	regoInput, err := core.CreateRegoQueryInput(e.logger, input, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return nil, err
	}

	evaluator, err := e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, e.rondConfig.ResponseFlow.PolicyName, regoInput, e.opaEvaluatorOptions)
	if err != nil {
		return nil, err
	}

	bodyToProxy, err := evaluator.Evaluate(e.logger, e.policyEvaluationOptions)
	if err != nil {
		return nil, err
	}

	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		return nil, err
	}

	return marshalledBody, nil
}
