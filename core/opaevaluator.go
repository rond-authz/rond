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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
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
	PolicyName    string       `json:"policyName"`
	GenerateQuery bool         `json:"generateQuery"`
	QueryOptions  QueryOptions `json:"queryOptions"`
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
	Partial(ctx context.Context) (*rego.PartialQueries, error)
}

var Unknowns = []string{"data.resources"}

type OPAEvaluator struct {
	PolicyEvaluator Evaluator
	PolicyName      string

	context     context.Context
	mongoClient types.IMongoClient
}
type PartialResultsEvaluatorConfigKey struct{}

type PartialResultsEvaluators map[string]PartialEvaluator

type PartialEvaluator struct {
	PartialEvaluator *rego.PartialResult
}

func createPartialEvaluator(ctx context.Context, logger *logrus.Entry, policy string, opaModuleConfig *OPAModuleConfig, options *OPAEvaluatorOptions) (*PartialEvaluator, error) {
	logger.WithField("policyName", policy).Info("precomputing rego policy")

	policyEvaluatorTime := time.Now()
	partialResultEvaluator, err := newPartialResultEvaluator(ctx, policy, opaModuleConfig, options)
	if err != nil {
		return nil, err
	}

	logger.
		WithFields(logrus.Fields{
			"policyName":                   policy,
			"computationTimeMicroserconds": time.Since(policyEvaluatorTime).Microseconds,
		}).
		Info("precomputation time")

	return &PartialEvaluator{PartialEvaluator: partialResultEvaluator}, nil
}

func (policyEvaluators PartialResultsEvaluators) AddFromConfig(ctx context.Context, logger *logrus.Entry, opaModuleConfig *OPAModuleConfig, rondConfig *RondConfig, options *OPAEvaluatorOptions) error {
	allowPolicy := rondConfig.RequestFlow.PolicyName
	responsePolicy := rondConfig.ResponseFlow.PolicyName

	logger.
		WithFields(logrus.Fields{
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

func NewPrintHook(w io.Writer, policy string) print.Hook {
	return printHook{
		w:          w,
		policyName: policy,
	}
}

type printHook struct {
	w          io.Writer
	policyName string
}

type LogPrinter struct {
	Level      int    `json:"level"`
	Message    string `json:"msg"`
	Time       int64  `json:"time"`
	PolicyName string `json:"policyName"`
}

func (h printHook) Print(_ print.Context, message string) error {
	structMessage := LogPrinter{
		Level:      10,
		Message:    message,
		Time:       time.Now().UnixNano() / 1000,
		PolicyName: h.policyName,
	}
	msg, err := json.Marshal(structMessage)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(h.w, string(msg))
	return err
}

type OPAEvaluatorOptions struct {
	EnablePrintStatements bool
	MongoClient           types.IMongoClient
}

func NewOPAEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, input []byte, options *OPAEvaluatorOptions) (*OPAEvaluator, error) {
	if options == nil {
		options = &OPAEvaluatorOptions{}
	}
	inputTerm, err := ast.ParseTerm(string(input))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedInputParse, err)
	}

	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)
	query := rego.New(
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.ParsedInput(inputTerm.Value),
		rego.Unknowns(Unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		rego.EnablePrintStatements(options.EnablePrintStatements),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		custom_builtins.GetHeaderFunction,
		custom_builtins.MongoFindOne,
		custom_builtins.MongoFindMany,
	)

	return &OPAEvaluator{
		PolicyEvaluator: query,
		PolicyName:      policy,

		context:     ctx,
		mongoClient: options.MongoClient,
	}, nil
}

func (config *OPAModuleConfig) CreateQueryEvaluator(ctx context.Context, logger *logrus.Entry, policy string, input []byte, options *OPAEvaluatorOptions) (*OPAEvaluator, error) {
	// TODO: remove logger and set in sdk
	logger.WithFields(logrus.Fields{
		"policyName": policy,
	}).Info("Policy to be evaluated")

	opaEvaluatorInstanceTime := time.Now()
	evaluator, err := NewOPAEvaluator(ctx, policy, config, input, options)
	if err != nil {
		logger.WithError(err).Error(ErrEvaluatorCreationFailed)
		return nil, err
	}
	logger.
		WithField("evaluatorCreationTimeMicroseconds", time.Since(opaEvaluatorInstanceTime).Microseconds()).
		Trace("evaluator creation time")
	return evaluator, nil
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
		ctx = mongoclient.WithMongoClient(ctx, evaluatorOptions.MongoClient)
		options = append(options, custom_builtins.MongoFindOne, custom_builtins.MongoFindMany)
	}
	regoInstance := rego.New(options...)

	results, err := regoInstance.PartialResult(ctx)
	return &results, err
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

func (evaluator *OPAEvaluator) partiallyEvaluate(logger *logrus.Entry, options *PolicyEvaluationOptions) (primitive.M, error) {
	if options == nil {
		options = &PolicyEvaluationOptions{}
	}
	opaEvaluationTimeStart := time.Now()
	partialResults, err := evaluator.PolicyEvaluator.Partial(evaluator.getContext())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPartialPolicyEvalFailed, err.Error())
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)

	options.metrics().PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	fields := logrus.Fields{
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

	logger.WithFields(logrus.Fields{
		"allowed": true,
		"query":   q,
	}).Tracef("policy results and query")

	return q, nil
}

func (evaluator *OPAEvaluator) Evaluate(logger *logrus.Entry, options *PolicyEvaluationOptions) (interface{}, error) {
	if options == nil {
		options = &PolicyEvaluationOptions{}
	}

	opaEvaluationTimeStart := time.Now()

	results, err := evaluator.PolicyEvaluator.Eval(evaluator.getContext())
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrPolicyEvalFailed, err.Error())
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)
	options.metrics().PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	allowed, responseBodyOverwriter := processResults(results)
	fields := logrus.Fields{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 evaluator.PolicyName,
		"partialEval":                false,
		"allowed":                    allowed,
		"resultsLength":              len(results),
	}
	addDataToLogFields(fields, options.AdditionalLogFields)

	logger.WithFields(fields).Debug("policy evaluation completed")

	logger.WithFields(logrus.Fields{
		"policyName": evaluator.PolicyName,
		"allowed":    allowed,
	}).Info("policy result")

	if allowed {
		return responseBodyOverwriter, nil
	}
	return nil, ErrPolicyEvalFailed
}

func (evaluator *OPAEvaluator) getContext() context.Context {
	ctx := evaluator.context
	if ctx == nil {
		ctx = context.Background()
	}
	if evaluator.mongoClient != nil {
		return mongoclient.WithMongoClient(ctx, evaluator.mongoClient)
	}
	return ctx
}

type PolicyEvaluationOptions struct {
	Metrics             *metrics.Metrics
	AdditionalLogFields map[string]string
}

func (evaluator *PolicyEvaluationOptions) metrics() metrics.Metrics {
	if evaluator.Metrics != nil {
		return *evaluator.Metrics
	}
	return metrics.SetupMetrics("rond")
}

// TODO: here permission is required? We could remove it?
func (evaluator *OPAEvaluator) PolicyEvaluation(logger *logrus.Entry, permission *RondConfig, options *PolicyEvaluationOptions) (interface{}, primitive.M, error) {
	if permission == nil {
		return nil, nil, ErrRondConfigNotExists
	}
	if permission.RequestFlow.GenerateQuery {
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
