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
	PartialEvaluator *rego.PartialResult
}

func createPartialEvaluator(ctx context.Context, logger logging.Logger, policy string, opaModuleConfig *OPAModuleConfig, options *OPAEvaluatorOptions) (*PartialEvaluator, error) {
	logger.WithField("policyName", policy).Info("precomputing rego policy")

	policyEvaluatorTime := time.Now()
	partialResultEvaluator, err := newPartialResultEvaluator(ctx, policy, opaModuleConfig, options)
	if err != nil {
		return nil, err
	}

	logger.
		WithFields(map[string]any{
			"policyName":                  policy,
			"computationTimeMicroseconds": time.Since(policyEvaluatorTime).Microseconds(),
		}).
		Info("precomputation time")

	return &PartialEvaluator{PartialEvaluator: partialResultEvaluator}, nil
}

func (policyEvaluators PartialResultsEvaluators) AddFromConfig(ctx context.Context, logger logging.Logger, opaModuleConfig *OPAModuleConfig, rondConfig *RondConfig, options *OPAEvaluatorOptions) error {
	allowPolicy := rondConfig.RequestFlow.PolicyName
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
		evaluator, err := createPartialEvaluator(ctx, logger, allowPolicy, opaModuleConfig, options)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrEvaluatorCreationFailed, err.Error())
		}

		policyEvaluators[allowPolicy] = *evaluator
	}

	if responsePolicy != "" {
		if _, ok := policyEvaluators[responsePolicy]; !ok {
			evaluator, err := createPartialEvaluator(ctx, logger, responsePolicy, opaModuleConfig, options)
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

		evaluator := eval.PartialEvaluator.Rego(
			rego.ParsedInput(inputTerm.Value),
			rego.EnablePrintStatements(options.EnablePrintStatements),
			rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		)

		return &OPAEvaluator{
			PolicyName:      policy,
			PolicyEvaluator: evaluator,

			context:     ctx,
			mongoClient: options.MongoClient,
		}, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrEvaluatorNotFound, policy)
}

func newPartialResultEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, evaluatorOptions *OPAEvaluatorOptions) (*rego.PartialResult, error) {
	if evaluatorOptions == nil {
		evaluatorOptions = &OPAEvaluatorOptions{}
	}
	if opaModuleConfig == nil {
		return nil, fmt.Errorf("OPAModuleConfig must not be nil")
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

	results, err := regoInstance.PartialResult(ctx)
	return &results, err
}
