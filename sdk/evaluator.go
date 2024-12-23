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
	"errors"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/audit"
	"github.com/rond-authz/rond/logging"
)

const userAgentHeaderKey = "user-agent"

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
	auditAgentPool          audit.AgentPool
}

func (e evaluator) Config() core.RondConfig {
	return e.rondConfig
}

type AuditOptions struct {
	AggregationID string
}

type EvaluateOptions struct {
	Logger logging.Logger
	Audit  AuditOptions
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

	evalInput, err := core.CreateRegoQueryInput(logger, rondInput, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return PolicyResult{}, err
	}

	opaEvaluatorOptions := e.evaluatorOptions.opaEvaluatorOptions(logger)

	auditAgent := e.auditAgentPool.New()
	ctx = audit.WithAuditCache(ctx, auditAgent)
	evaluatorAllowPolicy, err := e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, rondConfig.RequestFlow.PolicyName, opaEvaluatorOptions)
	if err != nil {
		return PolicyResult{}, err
	}

	// TODO: here if the evaluation result false, it is returned an error. This interface
	// for the sdk should be improved, since it should use the PolicyResult and return error
	// only if there is some error in policy evaluation.
	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(logger, evalInput, e.policyEvaluationOptions)

	if err != nil {
		logger.WithField("error", map[string]any{
			"policyName": rondConfig.RequestFlow.PolicyName,
			"message":    err.Error(),
		}).Error("RBAC policy evaluation failed")

		auditAgent.Trace(ctx, audit.Audit{
			AggregationID: options.Audit.AggregationID,
			Authorization: audit.AuthzInfo{
				Allowed:    false,
				PolicyName: rondConfig.RequestFlow.PolicyName,
			},
			Subject: audit.SubjectInfo{
				ID:     rondInput.User.ID,
				Groups: rondInput.User.Groups,
			},
			Request: audit.RequestInfo{
				Verb:      rondInput.Request.Method,
				Path:      rondInput.Request.Path,
				UserAgent: rondInput.Request.Headers.Get(userAgentHeaderKey),
			},
		})

		if errors.Is(err, core.ErrPolicyNotAllowed) {
			return PolicyResult{}, nil
		}
		return PolicyResult{}, err
	}

	var queryToProxy []byte
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	auditAgent.Trace(ctx, audit.Audit{
		AggregationID: options.Audit.AggregationID,
		Authorization: audit.AuthzInfo{
			Allowed:    true,
			PolicyName: rondConfig.RequestFlow.PolicyName,
		},
		Subject: audit.SubjectInfo{
			ID:     rondInput.User.ID,
			Groups: rondInput.User.Groups,
		},
		Request: audit.RequestInfo{
			Verb:      rondInput.Request.Method,
			Path:      rondInput.Request.Path,
			UserAgent: rondInput.Request.Headers.Get(userAgentHeaderKey),
		},
	})

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

	evalInput, err := core.CreateRegoQueryInput(logger, rondInput, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: rondConfig.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return nil, err
	}

	opaEvaluatorOptions := e.evaluatorOptions.opaEvaluatorOptions(logger)

	auditAgent := e.auditAgentPool.New()
	ctx = audit.WithAuditCache(ctx, auditAgent)
	evaluator, err := e.partialResultEvaluators.GetEvaluatorFromPolicy(ctx, e.rondConfig.ResponseFlow.PolicyName, opaEvaluatorOptions)
	if err != nil {
		return nil, err
	}

	bodyToProxy, err := evaluator.Evaluate(logger, evalInput, e.policyEvaluationOptions)
	if err != nil {
		auditAgent.Trace(ctx, audit.Audit{
			AggregationID: options.Audit.AggregationID,
			Authorization: audit.AuthzInfo{
				Allowed:    false,
				PolicyName: rondConfig.ResponseFlow.PolicyName,
			},
			Subject: audit.SubjectInfo{
				ID:     rondInput.User.ID,
				Groups: rondInput.User.Groups,
			},
			Request: audit.RequestInfo{
				Verb:      rondInput.Request.Method,
				Path:      rondInput.Request.Path,
				UserAgent: rondInput.Request.Headers.Get(userAgentHeaderKey),
			},
		})
		return nil, err
	}

	auditAgent.Trace(ctx, audit.Audit{
		AggregationID: options.Audit.AggregationID,
		Authorization: audit.AuthzInfo{
			Allowed:    true,
			PolicyName: rondConfig.ResponseFlow.PolicyName,
		},
		Subject: audit.SubjectInfo{
			ID:     rondInput.User.ID,
			Groups: rondInput.User.Groups,
		},
		Request: audit.RequestInfo{
			Verb:      rondInput.Request.Method,
			Path:      rondInput.Request.Path,
			UserAgent: rondInput.Request.Headers.Get(userAgentHeaderKey),
		},
	})

	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		return nil, err
	}

	return marshalledBody, nil
}
