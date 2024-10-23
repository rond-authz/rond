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
	"os"
	"strings"
	"time"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/logging"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

type PartialResultsEvaluators map[string]PartialEvaluator

type PartialEvaluator struct {
	partialEvaluator     *rego.PartialResult
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
		evaluator, err := createPartialEvaluator(ctx, logger, allowPolicy, opaModuleConfig, options, isFilterQuery)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrEvaluatorCreationFailed, err.Error())
		}
		policyEvaluators[allowPolicy] = *evaluator
	}

	if responsePolicy != "" {
		if _, ok := policyEvaluators[responsePolicy]; !ok {
			evaluator, err := createPartialEvaluator(ctx, logger, responsePolicy, opaModuleConfig, options, false)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrEvaluatorCreationFailed, err.Error())
			}

			policyEvaluators[responsePolicy] = *evaluator
		}
	}

	return nil
}

func (partialEvaluators PartialResultsEvaluators) GetEvaluatorFromPolicy(ctx context.Context, policy string, input []byte, options *OPAEvaluatorOptions) (*OPAEvaluator, error) {
	if options == nil {
		options = &OPAEvaluatorOptions{}
	}

	if eval, ok := partialEvaluators[policy]; ok {
		inputTerm, err := ast.ParseTerm(string(input))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFailedInputParse, err)
		}

		var evaluator Evaluator
		if eval.partialEvaluator != nil {
			evaluator = eval.partialEvaluator.Rego(
				rego.ParsedInput(inputTerm.Value),
				rego.EnablePrintStatements(options.EnablePrintStatements),
				rego.PrintHook(NewPrintHook(os.Stdout, policy)),
			)
		}

		return &OPAEvaluator{
			PolicyName: policy,

			policyEvaluator:      evaluator,
			preparedPartialQuery: eval.preparedPartialQuery,
			input:                input,
			context:              ctx,
			mongoClient:          options.MongoClient,
			generateQuery:        eval.preparedPartialQuery != nil,
		}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrEvaluatorNotFound, policy)
}

func newRegoInstanceBuilder(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, evaluatorOptions *OPAEvaluatorOptions) (*rego.Rego, context.Context, error) {
	if opaModuleConfig == nil {
		return nil, nil, fmt.Errorf("OPAModuleConfig must not be nil")
	}

	if evaluatorOptions == nil {
		evaluatorOptions = &OPAEvaluatorOptions{}
	}

	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)

	options := []func(*rego.Rego){
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.Unknowns(Unknowns),
		rego.EnablePrintStatements(evaluatorOptions.EnablePrintStatements),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
	}
	if evaluatorOptions.MongoClient != nil {
		ctx = custom_builtins.WithMongoClient(ctx, evaluatorOptions.MongoClient)
		options = append(options, custom_builtins.MongoFindOne, custom_builtins.MongoFindMany)
	}
	if evaluatorOptions.Logger != nil {
		ctx = logging.WithContext(ctx, evaluatorOptions.Logger)
	}
	regoInstance := rego.New(options...)

	return regoInstance, ctx, nil
}

func createPartialEvaluator(ctx context.Context, logger logging.Logger, policy string, opaModuleConfig *OPAModuleConfig, options *OPAEvaluatorOptions, isPartial bool) (*PartialEvaluator, error) {
	logger.WithField("policyName", policy).Info("precomputing rego policy")

	preparedPartialEvaluator := &PartialEvaluator{}

	policyEvaluatorTime := time.Now()

	regoInstance, regoCtx, err := newRegoInstanceBuilder(ctx, policy, opaModuleConfig, options)
	if err != nil {
		return nil, err
	}
	if isPartial {
		preparedPartialQuery, err := regoInstance.PrepareForPartial(regoCtx)
		if err != nil {
			return nil, err
		}
		preparedPartialEvaluator.preparedPartialQuery = &preparedPartialQuery
	} else {
		partialResultEvaluator, err := regoInstance.PartialResult(regoCtx)
		if err != nil {
			return nil, err
		}
		preparedPartialEvaluator.partialEvaluator = &partialResultEvaluator
	}

	logger.
		WithFields(map[string]any{
			"policyName":                  policy,
			"computationTimeMicroseconds": time.Since(policyEvaluatorTime).Microseconds(),
		}).
		Info("precomputation time")

	return preparedPartialEvaluator, nil
}
