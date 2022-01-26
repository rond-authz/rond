package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/opatranslator"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"

	"git.tools.mia-platform.eu/platform/core/rbac-service/custom_builtins"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Evaluator interface {
	Eval(ctx context.Context) (rego.ResultSet, error)
	Partial(ctx context.Context) (*rego.PartialQueries, error)
}

var unknowns = []string{"data.resources"}

type OPAEvaluator struct {
	PermissionQuery Evaluator
	Policy          string
}

func NewOPAEvaluator(policy string, opaModuleConfig *OPAModuleConfig, input []byte) (*OPAEvaluator, error) {

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
		rego.Unknowns(unknowns),
		rego.Capabilities(ast.CapabilitiesForThisVersion()),
		custom_builtins.GetHeaderFunction,
	)

	return &OPAEvaluator{
		PermissionQuery: query,
		Policy:          policy,
	}, nil
}

func createEvaluator(logger *logrus.Entry, req *http.Request, env EnvironmentVariables, policy string, responseBody interface{}) (*OPAEvaluator, error) {
	opaModuleConfig, err := GetOPAModuleConfig(req.Context())
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no OPA module configuration found in context")
		return nil, fmt.Errorf("no OPA module configuration found in context")
	}

	userInfo, err := retrieveUserBindingsAndRoles(logger, req, env)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		return nil, err
	}

	input, err := createRegoQueryInput(req, env, userInfo, responseBody)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed rego query input creation")
		return nil, fmt.Errorf("Failed rego query input creation: %s", err.Error())
	}
	logger.WithFields(logrus.Fields{
		"policyName": policy,
	}).Info("Policy to be evaluated")

	logger.WithFields(logrus.Fields{
		"input": string(input),
	}).Trace("input object passed to the evaluator")

	evaluator, err := NewOPAEvaluator(policy, opaModuleConfig, input)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		return nil, err
	}
	return evaluator, nil
}

func (evaluator *OPAEvaluator) partiallyEvaluate(logger *logrus.Entry) (primitive.M, error) {
	partialResults, err := evaluator.PermissionQuery.Partial(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("Policy Evaluation has failed when partially evaluating the query: %s", err.Error())
	}

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

func (evaluator *OPAEvaluator) evaluate(logger *logrus.Entry) (interface{}, error) {
	results, err := evaluator.PermissionQuery.Eval(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("Policy Evaluation has failed when evaluating the query: %s", err.Error())
	}

	if results.Allowed() {
		logger.WithFields(logrus.Fields{
			"allowed":       results.Allowed(),
			"resultsLength": len(results),
		}).Tracef("policy results")
		return nil, nil
	}

	// The results returned by OPA are a list of Results object with fields:
	// - Expressions: list of list
	// - Bindings: object
	// e.g. [{Expressions:[[map["element": true]]] Bindings:map[]}]
	// Since we are ALWAYS querying ONE specifc policy the result length could not be greater than 1

	if len(results) == 1 {
		if exprs := results[0].Expressions; len(exprs) == 1 {
			if value, ok := exprs[0].Value.([]interface{}); ok && value != nil && len(value) != 0 {
				return value[0], nil
			}
		}
	}
	logger.Error("policy resulted in not allowed")
	return nil, fmt.Errorf("RBAC policy evaluation failed, user is not allowed")
}

func (evaluator *OPAEvaluator) PolicyEvaluation(logger *logrus.Entry, permission *XPermission) (interface{}, primitive.M, error) {
	if permission.ResourceFilter.RowFilter.Enabled {
		query, err := evaluator.partiallyEvaluate(logger)
		return nil, query, err
	}
	dataFromEvaluation, err := evaluator.evaluate(logger)
	if err != nil {
		return nil, nil, err
	}

	return dataFromEvaluation, nil, nil
}

func createRegoQueryInput(req *http.Request, env EnvironmentVariables, user types.User, responseBody interface{}) ([]byte, error) {
	userProperties := make(map[string]interface{})
	_, err := unmarshalHeader(req.Header, env.UserPropertiesHeader, &userProperties)
	if err != nil {
		return nil, fmt.Errorf("user properties header is not valid: %s", err.Error())
	}

	userGroup := make([]string, 0)
	userGroupsNotSplitted := req.Header.Get(env.UserGroupsHeader)
	if userGroupsNotSplitted != "" {
		userGroup = strings.Split(userGroupsNotSplitted, ",")
	}

	input := Input{
		ClientType: req.Header.Get(env.ClientTypeHeader),
		Request: InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: mux.Vars(req),
		},
		Response: InputResponse{
			Body: responseBody,
		},
		User: InputUser{
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
			Properties: userProperties,
			Groups:     userGroup,
		},
	}

	shouldParseJSONBody := hasApplicationJSONContentType(req.Header) &&
		req.ContentLength > 0 &&
		(req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut)

	if shouldParseJSONBody {
		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed request body parse: %s", err.Error())
		}
		if err := json.Unmarshal(bodyBytes, &input.Request.Body); err != nil {
			return nil, fmt.Errorf("failed request body deserialization: %s", err.Error())
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed input JSON encode: %v", err)
	}
	return inputBytes, nil
}
