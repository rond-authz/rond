// Copyright 2021 Mia srl
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
	"path/filepath"
	"time"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/metrics"
	"github.com/rond-authz/rond/types"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RondConfig struct {
	RequestFlow  RequestFlow       `json:"requestFlow"`
	ResponseFlow ResponseFlow      `json:"responseFlow"`
	Options      PermissionOptions `json:"options"`
}

type QueryOptions struct {
	HeaderName string `json:"headerName"`
}

type RequestFlow struct {
	PolicyName      string       `json:"policyName"`
	GenerateQuery   bool         `json:"generateQuery"`
	QueryOptions    QueryOptions `json:"queryOptions"`
	PreventBodyLoad bool         `json:"preventBodyLoad"`
}

type ResponseFlow struct {
	PolicyName string `json:"policyName"`
}

type PermissionOptions struct {
	EnableResourcePermissionsMapOptimization bool `json:"enableResourcePermissionsMapOptimization"`
	IgnoreTrailingSlash                      bool `json:"ignoreTrailingSlash,omitempty"`
}

type Evaluator interface {
	Eval(ctx context.Context) (rego.ResultSet, error)
}

var Unknowns = []string{"data.resources"}

type OPAEvaluator struct {
	policyEvaluator      Evaluator
	preparedPartialQuery *rego.PreparedPartialQuery
	PolicyName           string

	context       context.Context
	mongoClient   custom_builtins.IMongoClient
	generateQuery bool
	logger        logging.Logger
	input         []byte
}

type OPAEvaluatorOptions struct {
	EnablePrintStatements bool
	MongoClient           custom_builtins.IMongoClient
	Logger                logging.Logger
}

func (evaluator *OPAEvaluator) partiallyEvaluate(logger logging.Logger, options *PolicyEvaluationOptions) (primitive.M, error) {
	if options == nil {
		options = &PolicyEvaluationOptions{}
	}
	opaEvaluationTimeStart := time.Now()
	inputTerm, err := ast.ParseTerm(string(evaluator.input))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedInputParse, err)
	}

	partialResults, err := evaluator.preparedPartialQuery.Partial(evaluator.getContext(), rego.EvalParsedInput(inputTerm.Value))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPartialPolicyEvalFailed, err.Error())
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)

	options.metrics().PolicyEvaluationDurationMilliseconds.With(metrics.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	fields := map[string]any{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 evaluator.PolicyName,
		"partialEval":                true,
		"allowed":                    true,
	}
	addDataToLogFields(fields, options.AdditionalLogFields)

	logger.WithFields(fields).Debug("policy evaluation completed")

	client := opatranslator.OPAClient{}
	q, err := client.ProcessQuery(partialResults)
	if err != nil {
		return nil, err
	}

	logger.WithFields(map[string]any{
		"allowed": true,
		"query":   q,
	}).Trace("policy results and query")

	return q, nil
}

func (evaluator *OPAEvaluator) Evaluate(logger logging.Logger, options *PolicyEvaluationOptions) (interface{}, error) {
	if options == nil {
		options = &PolicyEvaluationOptions{}
	}

	opaEvaluationTimeStart := time.Now()

	results, err := evaluator.policyEvaluator.Eval(evaluator.getContext())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPolicyEvalFailed, err.Error())
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)
	options.metrics().PolicyEvaluationDurationMilliseconds.With(metrics.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	allowed, responseBodyOverwriter := processResults(results)
	fields := map[string]any{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 evaluator.PolicyName,
		"partialEval":                false,
		"allowed":                    allowed,
		"resultsLength":              len(results),
	}
	addDataToLogFields(fields, options.AdditionalLogFields)

	logger.WithFields(fields).Debug("policy evaluation completed")

	logger.WithFields(map[string]any{
		"policyName": evaluator.PolicyName,
		"allowed":    allowed,
	}).Info("policy result")

	if allowed {
		return responseBodyOverwriter, nil
	}
	return nil, ErrPolicyNotAllowed
}

func (evaluator *OPAEvaluator) getContext() context.Context {
	ctx := evaluator.context
	if ctx == nil {
		ctx = context.Background()
	}
	if evaluator.mongoClient != nil {
		ctx = custom_builtins.WithMongoClient(ctx, evaluator.mongoClient)
	}
	if evaluator.logger != nil {
		ctx = logging.WithContext(ctx, evaluator.logger)
	}
	return ctx
}

type PolicyEvaluationOptions struct {
	Metrics             *metrics.Metrics
	AdditionalLogFields map[string]string
}

func (evaluator *PolicyEvaluationOptions) metrics() *metrics.Metrics {
	if evaluator.Metrics != nil {
		return evaluator.Metrics
	}
	return metrics.NoOpMetrics()
}

func (evaluator *OPAEvaluator) PolicyEvaluation(logger logging.Logger, options *PolicyEvaluationOptions) (interface{}, primitive.M, error) {
	if evaluator.generateQuery {
		query, err := evaluator.partiallyEvaluate(logger, options)
		return nil, query, err
	}
	dataFromEvaluation, err := evaluator.Evaluate(logger, options)
	if err != nil {
		return nil, nil, err
	}
	return dataFromEvaluation, nil, nil
}

func buildRolesMap(roles []types.Role) map[string][]string {
	var rolesMap = make(map[string][]string, 0)
	for _, role := range roles {
		rolesMap[role.RoleID] = role.Permissions
	}
	return rolesMap
}

type OPAModuleConfig struct {
	Name    string
	Content string
}

type PermissionOnResourceKey string

type PermissionsOnResourceMap map[PermissionOnResourceKey]bool

func buildPermissionOnResourceKey(permission string, resourceType string, resourceId string) PermissionOnResourceKey {
	return PermissionOnResourceKey(fmt.Sprintf("%s:%s:%s", permission, resourceType, resourceId))
}

func LoadRegoModule(rootDirectory string) (*OPAModuleConfig, error) {
	var regoModulePath string
	//#nosec G104 -- Produces a false positive
	filepath.Walk(rootDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if regoModulePath != "" {
			return nil
		}

		if filepath.Ext(path) == ".rego" {
			regoModulePath = path
		}
		return nil
	})

	if regoModulePath == "" {
		return nil, ErrMissingRegoModules
	}
	fileContent, err := utils.ReadFile(regoModulePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRegoModuleReadFailed, err.Error())
	}

	return &OPAModuleConfig{
		Name:    filepath.Base(regoModulePath),
		Content: string(fileContent),
	}, nil
}

func processResults(results rego.ResultSet) (allowed bool, responseBodyOverwriter any) {
	// Use strict allowed check for basic request flow allow policies.
	if results.Allowed() {
		allowed = true
		return
	}

	// Here extract first result set to get the response body for the response policy evaluation.
	// The results returned by OPA are a list of Results object with fields:
	// - Expressions: list of list
	// - Bindings: object
	// e.g. [{Expressions:[[map["element": true]]] Bindings:map[]}]
	// Since we are ALWAYS querying ONE specific policy the result length could not be greater than 1
	if len(results) == 1 {
		if exprs := results[0].Expressions; len(exprs) == 1 {
			if value, ok := exprs[0].Value.([]interface{}); ok && value != nil && len(value) != 0 {
				allowed = true
				responseBodyOverwriter = value[0]
				return
			}
		}
	}

	return
}
