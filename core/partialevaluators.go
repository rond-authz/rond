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
	"fmt"
	"time"

	"github.com/rond-authz/rond/logging"

	"github.com/open-policy-agent/opa/rego"
)

type PartialResultsEvaluators map[string]PartialEvaluator

type PartialEvaluator struct {
	preparedEvalQuery    *rego.PreparedEvalQuery
	preparedPartialQuery *rego.PreparedPartialQuery
}

func (policyEvaluators PartialResultsEvaluators) AddFromConfig(ctx context.Context, logger logging.Logger, opaModuleConfig *OPAModuleConfig, rondConfig *RondConfig, options *OPAEvaluatorOptions) error {
	allowPolicy := rondConfig.RequestFlow.PolicyName
	isFilterQuery := rondConfig.RequestFlow.GenerateQuery
	responsePolicy := rondConfig.ResponseFlow.PolicyName

	logger.
		WithFields(map[string]any{
			"policyName":         allowPolicy,
			"responsePolicyName": responsePolicy,
		}).
		Info("precomputing rego queries")

	if allowPolicy == "" {
		return fmt.Errorf("%w: allow policy is required", ErrInvalidConfig)
	}

	if _, ok := policyEvaluators[allowPolicy]; !ok {
		evaluator, err := createPartialEvaluator(logger, allowPolicy, opaModuleConfig, options, isFilterQuery)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrEvaluatorCreationFailed, err.Error())
		}
		policyEvaluators[allowPolicy] = *evaluator
	}

	if responsePolicy != "" {
		if _, ok := policyEvaluators[responsePolicy]; !ok {
			evaluator, err := createPartialEvaluator(logger, responsePolicy, opaModuleConfig, options, false)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrEvaluatorCreationFailed, err.Error())
			}

			policyEvaluators[responsePolicy] = *evaluator
		}
	}

	return nil
}

func (partialEvaluators PartialResultsEvaluators) GetEvaluatorFromPolicy(ctx context.Context, policy string, options *OPAEvaluatorOptions) (*OPAEvaluator, error) {
	if options == nil {
		options = &OPAEvaluatorOptions{}
	}

	if eval, ok := partialEvaluators[policy]; ok {
		return &OPAEvaluator{
			PolicyName: policy,

			evaluator:     eval,
			context:       ctx,
			mongoClient:   options.MongoClient,
			generateQuery: eval.preparedPartialQuery != nil,
		}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrEvaluatorNotFound, policy)
}

func createPartialEvaluator(logger logging.Logger, policy string, opaModuleConfig *OPAModuleConfig, options *OPAEvaluatorOptions, isPartial bool) (*PartialEvaluator, error) {
	logger.WithField("policyName", policy).Info("precomputing rego policy")

	preparedPartialEvaluator := &PartialEvaluator{}

	policyEvaluatorTime := time.Now()

	regoInstance, err := newRegoInstanceBuilder(policy, opaModuleConfig, options)
	if err != nil {
		return nil, err
	}
	if isPartial {
		preparedPartialQuery, err := regoInstance.PrepareForPartial(context.TODO())
		if err != nil {
			return nil, err
		}
		preparedPartialEvaluator.preparedPartialQuery = &preparedPartialQuery
	} else {
		partialResultEvaluator, err := regoInstance.PrepareForEval(context.TODO())
		if err != nil {
			return nil, err
		}
		preparedPartialEvaluator.preparedEvalQuery = &partialResultEvaluator
	}

	logger.
		WithFields(map[string]any{
			"policyName":                  policy,
			"computationTimeMicroseconds": time.Since(policyEvaluatorTime).Microseconds(),
		}).
		Info("precomputation time")

	return preparedPartialEvaluator, nil
}
