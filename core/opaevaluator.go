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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/rond-authz/rond/custom_builtins"

	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Evaluator interface {
	Eval(ctx context.Context) (rego.ResultSet, error)
	Partial(ctx context.Context) (*rego.PartialQueries, error)
}

var Unknowns = []string{"data.resources"}

type OPAEvaluator struct {
	PolicyEvaluator Evaluator
	PolicyName      string
	Context         context.Context
}
type PartialResultsEvaluatorConfigKey struct{}

type PartialResultsEvaluators map[string]PartialEvaluator

type PartialEvaluator struct {
	PartialEvaluator *rego.PartialResult
}

func createPartialEvaluator(policy string, ctx context.Context, mongoClient types.IMongoClient, oas *openapi.OpenAPISpec, opaModuleConfig *OPAModuleConfig, env config.EnvironmentVariables) (*PartialEvaluator, error) {
	glogger.Get(ctx).Infof("precomputing rego query for allow policy: %s", policy)

	policyEvaluatorTime := time.Now()
	partialResultEvaluator, err := NewPartialResultEvaluator(ctx, policy, opaModuleConfig, mongoClient, env)
	if err == nil {
		glogger.Get(ctx).Infof("computed rego query for policy: %s in %s", policy, time.Since(policyEvaluatorTime))
		return &PartialEvaluator{
			PartialEvaluator: partialResultEvaluator,
		}, nil
	}
	return nil, err
}

func SetupEvaluators(ctx context.Context, mongoClient types.IMongoClient, oas *openapi.OpenAPISpec, opaModuleConfig *OPAModuleConfig, env config.EnvironmentVariables) (PartialResultsEvaluators, error) {
	policyEvaluators := PartialResultsEvaluators{}
	for path, OASContent := range oas.Paths {
		for verb, verbConfig := range OASContent {
			if verbConfig.PermissionV2 == nil {
				continue
			}

			allowPolicy := verbConfig.PermissionV2.RequestFlow.PolicyName
			responsePolicy := verbConfig.PermissionV2.ResponseFlow.PolicyName

			glogger.Get(ctx).Infof("precomputing rego queries for API: %s %s. Allow policy: %s. Response policy: %s.", verb, path, allowPolicy, responsePolicy)
			if allowPolicy == "" {
				// allow policy is required, if missing assume the API has no valid x-rond configuration.
				continue
			}

			if _, ok := policyEvaluators[allowPolicy]; !ok {
				evaluator, err := createPartialEvaluator(allowPolicy, ctx, mongoClient, oas, opaModuleConfig, env)

				if err != nil {
					return nil, fmt.Errorf("error during evaluator creation: %s", err.Error())
				}

				policyEvaluators[allowPolicy] = *evaluator
			}

			if responsePolicy != "" {
				if _, ok := policyEvaluators[responsePolicy]; !ok {
					evaluator, err := createPartialEvaluator(responsePolicy, ctx, mongoClient, oas, opaModuleConfig, env)

					if err != nil {
						return nil, fmt.Errorf("error during evaluator creation: %s", err.Error())
					}

					policyEvaluators[responsePolicy] = *evaluator
				}
			}
		}
	}
	return policyEvaluators, nil
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

func NewOPAEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, input []byte, env config.EnvironmentVariables) (*OPAEvaluator, error) {
	inputTerm, err := ast.ParseTerm(string(input))
	if err != nil {
		return nil, fmt.Errorf("failed input parse: %v", err)
	}

	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)
	query := rego.New(
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.ParsedInput(inputTerm.Value),
		rego.Unknowns(Unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		rego.EnablePrintStatements(env.LogLevel == config.TraceLogLevel),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		custom_builtins.GetHeaderFunction,
		custom_builtins.MongoFindOne,
		custom_builtins.MongoFindMany,
	)

	return &OPAEvaluator{
		PolicyEvaluator: query,
		PolicyName:      policy,
		Context:         ctx,
	}, nil
}

func CreateQueryEvaluator(ctx context.Context, logger *logrus.Entry, req *http.Request, env config.EnvironmentVariables, policy string, input []byte, responseBody interface{}) (*OPAEvaluator, error) {
	opaModuleConfig, err := GetOPAModuleConfig(req.Context())
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no OPA module configuration found in context")
		return nil, fmt.Errorf("no OPA module configuration found in context")
	}

	logger.WithFields(logrus.Fields{
		"policyName": policy,
	}).Info("Policy to be evaluated")

	opaEvaluatorInstanceTime := time.Now()
	evaluator, err := NewOPAEvaluator(ctx, policy, opaModuleConfig, input, env)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		return nil, err
	}
	logger.Tracef("OPA evaluator instantiated in: %+v", time.Since(opaEvaluatorInstanceTime))
	return evaluator, nil
}

func NewPartialResultEvaluator(ctx context.Context, policy string, opaModuleConfig *OPAModuleConfig, mongoClient types.IMongoClient, env config.EnvironmentVariables) (*rego.PartialResult, error) {
	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)

	options := []func(*rego.Rego){
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		rego.Unknowns(Unknowns),
		rego.EnablePrintStatements(env.LogLevel == config.TraceLogLevel),
		rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
	}
	if mongoClient != nil {
		options = append(options, custom_builtins.MongoFindOne, custom_builtins.MongoFindMany)
	}
	regoInstance := rego.New(options...)

	results, err := regoInstance.PartialResult(ctx)
	return &results, err
}

func (partialEvaluators PartialResultsEvaluators) GetEvaluatorFromPolicy(ctx context.Context, policy string, input []byte, logLevel string) (*OPAEvaluator, error) {
	if eval, ok := partialEvaluators[policy]; ok {
		inputTerm, err := ast.ParseTerm(string(input))
		if err != nil {
			return nil, fmt.Errorf("failed input parse: %v", err)
		}

		evaluator := eval.PartialEvaluator.Rego(
			rego.ParsedInput(inputTerm.Value),
			rego.EnablePrintStatements(logLevel == config.TraceLogLevel),
			rego.PrintHook(NewPrintHook(os.Stdout, policy)),
		)

		return &OPAEvaluator{
			PolicyName:      policy,
			PolicyEvaluator: evaluator,
			Context:         ctx,
		}, nil
	}
	return nil, fmt.Errorf("policy evaluator not found")
}

func (evaluator *OPAEvaluator) partiallyEvaluate(logger *logrus.Entry) (primitive.M, error) {
	opaEvaluationTimeStart := time.Now()
	partialResults, err := evaluator.PolicyEvaluator.Partial(evaluator.Context)
	if err != nil {
		return nil, fmt.Errorf("policy Evaluation has failed when partially evaluating the query: %s", err.Error())
	}
	routerInfo, err := openapi.GetRouterInfo(evaluator.Context)
	if err != nil {
		return nil, err
	}
	m, err := metrics.GetFromContext(evaluator.Context)
	if err != nil {
		return nil, err
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)

	m.PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	logger.WithFields(logrus.Fields{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 evaluator.PolicyName,
		"partialEval":                true,
		"allowed":                    true,
		"matchedPath":                routerInfo.MatchedPath,
		"requestedPath":              routerInfo.RequestedPath,
		"method":                     routerInfo.Method,
	}).Debug("policy evaluation completed")

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

func (evaluator *OPAEvaluator) Evaluate(logger *logrus.Entry) (interface{}, error) {
	opaEvaluationTimeStart := time.Now()
	results, err := evaluator.PolicyEvaluator.Eval(evaluator.Context)
	if err != nil {
		return nil, fmt.Errorf("policy Evaluation has failed when evaluating the query: %s", err.Error())
	}
	routerInfo, err := openapi.GetRouterInfo(evaluator.Context)
	if err != nil {
		return nil, err
	}
	m, err := metrics.GetFromContext(evaluator.Context)
	if err != nil {
		return nil, err
	}

	opaEvaluationTime := time.Since(opaEvaluationTimeStart)

	m.PolicyEvaluationDurationMilliseconds.With(prometheus.Labels{
		"policy_name": evaluator.PolicyName,
	}).Observe(float64(opaEvaluationTime.Milliseconds()))

	logger.WithFields(logrus.Fields{
		"evaluationTimeMicroseconds": opaEvaluationTime.Microseconds(),
		"policyName":                 evaluator.PolicyName,
		"partialEval":                false,
		"allowed":                    results.Allowed(),
		"matchedPath":                routerInfo.MatchedPath,
		"requestedPath":              routerInfo.RequestedPath,
		"method":                     routerInfo.Method,
	}).Debug("policy evaluation completed")

	if results.Allowed() {
		logger.WithFields(logrus.Fields{
			"policyName":    evaluator.PolicyName,
			"allowed":       results.Allowed(),
			"resultsLength": len(results),
		}).Tracef("policy results")
		return nil, nil
	}

	// The results returned by OPA are a list of Results object with fields:
	// - Expressions: list of list
	// - Bindings: object
	// e.g. [{Expressions:[[map["element": true]]] Bindings:map[]}]
	// Since we are ALWAYS querying ONE specific policy the result length could not be greater than 1
	if len(results) == 1 {
		if exprs := results[0].Expressions; len(exprs) == 1 {
			if value, ok := exprs[0].Value.([]interface{}); ok && value != nil && len(value) != 0 {
				return value[0], nil
			}
		}
	}
	logger.WithFields(logrus.Fields{
		"policyName": evaluator.PolicyName,
	}).Error("policy resulted in not allowed")
	return nil, fmt.Errorf("RBAC policy evaluation failed, user is not allowed")
}

func (evaluator *OPAEvaluator) PolicyEvaluation(logger *logrus.Entry, permission *openapi.RondConfig) (interface{}, primitive.M, error) {
	if permission.RequestFlow.GenerateQuery {
		query, err := evaluator.partiallyEvaluate(logger)
		return nil, query, err
	}
	dataFromEvaluation, err := evaluator.Evaluate(logger)
	if err != nil {
		return nil, nil, err
	}
	return dataFromEvaluation, nil, nil
}

type RegoInputOptions struct {
	EnableResourcePermissionsMapOptimization bool
}

func CreateRegoQueryInput(
	logger *logrus.Entry,
	input Input,
	options RegoInputOptions,
) ([]byte, error) {
	opaInputCreationTime := time.Now()

	input.buildOptimizedResourcePermissionsMap(logger, options.EnableResourcePermissionsMapOptimization)

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed input JSON encode: %v", err)
	}
	logger.Tracef("OPA input rego creation in: %+v", time.Since(opaInputCreationTime))
	return inputBytes, nil
}

func buildRolesMap(roles []types.Role) map[string][]string {
	var rolesMap = make(map[string][]string, 0)
	for _, role := range roles {
		rolesMap[role.RoleID] = role.Permissions
	}
	return rolesMap
}

func WithPartialResultsEvaluators(requestContext context.Context, evaluators PartialResultsEvaluators) context.Context {
	return context.WithValue(requestContext, PartialResultsEvaluatorConfigKey{}, evaluators)
}

// GetPartialResultsEvaluators can be used by a request handler to get PartialResult evaluator instance from context.
func GetPartialResultsEvaluators(requestContext context.Context) (PartialResultsEvaluators, error) {
	evaluators, ok := requestContext.Value(PartialResultsEvaluatorConfigKey{}).(PartialResultsEvaluators)
	if !ok {
		return nil, fmt.Errorf("no policy evaluators found in request context")
	}

	return evaluators, nil
}

// TODO: This should be made private in the future.
type OPAModuleConfigKey struct{}

type OPAModuleConfig struct {
	Name    string
	Content string
}

func WithOPAModuleConfig(requestContext context.Context, permission *OPAModuleConfig) context.Context {
	return context.WithValue(requestContext, OPAModuleConfigKey{}, permission)
}

// GetOPAModuleConfig can be used by a request handler to get OPAModuleConfig instance from its context.
func GetOPAModuleConfig(requestContext context.Context) (*OPAModuleConfig, error) {
	permission, ok := requestContext.Value(OPAModuleConfigKey{}).(*OPAModuleConfig)
	if !ok {
		return nil, fmt.Errorf("no opa module config found in request context")
	}

	return permission, nil
}

type Input struct {
	Request    InputRequest  `json:"request"`
	Response   InputResponse `json:"response"`
	ClientType string        `json:"clientType,omitempty"`
	User       InputUser     `json:"user"`
}

func (input *Input) buildOptimizedResourcePermissionsMap(logger *logrus.Entry, enableResourcePermissionsMapOptimization bool) {
	if !enableResourcePermissionsMapOptimization {
		return
	}
	logger.Info("preparing optimized resourcePermissionMap for OPA evaluator")
	opaPermissionsMapTime := time.Now()

	user := input.User
	permissionsOnResourceMap := make(PermissionsOnResourceMap, 0)
	rolesMap := buildRolesMap(user.Roles)
	for _, binding := range user.Bindings {
		for _, role := range binding.Roles {
			rolePermissions, ok := rolesMap[role]
			if !ok {
				continue
			}
			for _, permission := range rolePermissions {
				key := buildPermissionOnResourceKey(permission, binding.Resource.ResourceType, binding.Resource.ResourceID)
				permissionsOnResourceMap[key] = true
			}
		}
		for _, permission := range binding.Permissions {
			key := buildPermissionOnResourceKey(permission, binding.Resource.ResourceType, binding.Resource.ResourceID)
			permissionsOnResourceMap[key] = true
		}
	}
	input.User.ResourcePermissionsMap = permissionsOnResourceMap
	logger.WithField("resourcePermissionMapCreationTime", fmt.Sprintf("%+v", time.Since(opaPermissionsMapTime))).Tracef("resource permission map creation")
}

type InputRequest struct {
	Body       interface{}       `json:"body,omitempty"`
	Headers    http.Header       `json:"headers,omitempty"`
	Query      url.Values        `json:"query,omitempty"`
	PathParams map[string]string `json:"pathParams,omitempty"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
}

type InputResponse struct {
	Body interface{} `json:"body,omitempty"`
}

type InputUser struct {
	Properties             map[string]interface{}   `json:"properties,omitempty"`
	Groups                 []string                 `json:"groups,omitempty"`
	Bindings               []types.Binding          `json:"bindings,omitempty"`
	Roles                  []types.Role             `json:"roles,omitempty"`
	ResourcePermissionsMap PermissionsOnResourceMap `json:"resourcePermissionsMap,omitempty"`
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
		return nil, fmt.Errorf("no rego module found in directory")
	}
	fileContent, err := utils.ReadFile(regoModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed rego file read: %s", err.Error())
	}

	return &OPAModuleConfig{
		Name:    filepath.Base(regoModulePath),
		Content: string(fileContent),
	}, nil
}

func InputFromRequest(
	req *http.Request,
	user types.User,
	clientTypeHeaderKey string,
	pathParams map[string]string,
	responseBody any,
) (Input, error) {
	shouldParseJSONBody := utils.HasApplicationJSONContentType(req.Header) &&
		req.ContentLength > 0 &&
		(req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodDelete)

	var requestBody any
	if shouldParseJSONBody {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return Input{}, fmt.Errorf("failed request body parse: %s", err.Error())
		}
		if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
			return Input{}, fmt.Errorf("failed request body deserialization: %s", err.Error())
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return Input{
		ClientType: req.Header.Get(clientTypeHeaderKey),
		Request: InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: pathParams,
			Body:       requestBody,
		},
		Response: InputResponse{
			Body: responseBody,
		},
		User: InputUser{
			Properties: user.Properties,
			Groups:     user.UserGroups,
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
		},
	}, nil
}
