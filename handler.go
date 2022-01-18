package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"rbac-service/internal/opatranslator"
	"rbac-service/internal/types"
	"rbac-service/internal/utils"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	env, err := GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context")
		return
	}

	permission, err := GetXPermission(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no policy permission found in context")
		failResponse(w, "no policy permission found in context")
		return
	}

	evaluator, err := createEvaluator(logger, req, w, env, permission)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		failResponse(w, err.Error())
		return
	}

	_, query, err := Evaluate(logger, permission, *evaluator, req)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("RBAC policy evaluation failed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed")
		return
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
			failResponseWithCode(w, http.StatusForbidden, "Error while marshaling row filter query")
			return
		}
	}

	queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
	if permission.ResourceFilter.RowFilter.HeaderKey != "" {
		queryHeaderKey = permission.ResourceFilter.RowFilter.HeaderKey
	}
	if query != nil {
		req.Header.Set(queryHeaderKey, string(queryToProxy))
	}

	ReverseProxy(env, w, req)
}

func ReverseProxy(env EnvironmentVariables, w http.ResponseWriter, req *http.Request) {
	targetHostFromEnv := env.TargetServiceHost

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Host = targetHostFromEnv
			req.URL.Scheme = URL_SCHEME
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
		},
	}
	proxy.ServeHTTP(w, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	env, err := GetEnv(requestContext)
	if err != nil {
		glogger.Get(requestContext).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context")
		return
	}
	ReverseProxy(env, w, req)
}

func createEvaluator(logger *logrus.Entry, req *http.Request, w http.ResponseWriter, env EnvironmentVariables, permission *XPermission) (*OPAEvaluator, error) {

	opaModuleConfig, err := GetOPAModuleConfig(req.Context())
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no OPA module configuration found in context")
		return nil, fmt.Errorf("no OPA module configuration found in context")
	}

	userInfo, err := retrieveUserBindingsAndRoles(logger, req, w, env)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		return nil, err
	}

	input, err := createRegoQueryInput(req, env, userInfo)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("user properties header is not valid")
		return nil, fmt.Errorf("Failed rego query input creation: %s", err.Error())
	}

	logger.WithFields(logrus.Fields{
		"policyName": permission.AllowPermission,
	}).Info("Policy to be evaluated")

	logger.WithFields(logrus.Fields{
		"input": string(input),
	}).Trace("input object passed to the evaluator")

	evaluator, err := NewOPAEvaluator(permission.AllowPermission, opaModuleConfig, input)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		return nil, err
	}
	return evaluator, nil
}

func Evaluate(logger *logrus.Entry, permission *XPermission, evaluator OPAEvaluator, req *http.Request) (bool, primitive.M, error) {
	if permission.ResourceFilter.RowFilter.Enabled {
		partialResults, err := evaluator.PermissionQuery.Partial(context.TODO())
		if err != nil {
			return false, nil, fmt.Errorf("Policy Evaluation has failed when partially evaluating the query: %s", err.Error())
		}
		client := opatranslator.OPAClient{}
		q, err := client.ProcessQuery(partialResults)
		if err != nil {
			return false, nil, fmt.Errorf("Policy Evaluation has failed when processing query: %s", err.Error())
		}
		logger.WithFields(logrus.Fields{
			"allowed": true,
			"query":   q,
		}).Tracef("policy results and query")
		return true, q, nil
	}

	results, err := evaluator.PermissionQuery.Eval(context.TODO())
	if err != nil {
		return false, nil, fmt.Errorf("Policy Evaluation has failed when evaluating the query: %s", err.Error())
	}

	logger.WithFields(logrus.Fields{
		"allowed":       results.Allowed(),
		"resultsLength": len(results),
	}).Tracef("policy results")

	if !results.Allowed() {
		logger.Error("policy resulted in not allowed")
		return false, nil, fmt.Errorf("RBAC policy evaluation failed, user is not allowed")
	}
	return true, nil, nil
}

func rolesIdsFromBindings(bindings []types.Binding) []string {
	rolesIds := []string{}
	for _, binding := range bindings {
		for _, role := range binding.Roles {
			if !utils.Contains(rolesIds, role) {
				rolesIds = append(rolesIds, role)
			}
		}
	}
	return rolesIds
}

func retrieveUserBindingsAndRoles(logger *logrus.Entry, req *http.Request, w http.ResponseWriter, env EnvironmentVariables) (types.User, error) {
	requestContext := req.Context()
	mongoClient, err := GetMongoClientFromContext(requestContext)
	if err != nil {
		return types.User{}, fmt.Errorf("Unexpected error retrieving MongoDB Client from request context")
	}

	var user types.User

	user.UserGroups = strings.Split(req.Header.Get(env.UserGroupsHeader), ",")
	user.UserID = req.Header.Get(env.UserIdHeader)

	if mongoClient != nil && user.UserID != "" {

		user.UserBindings, err = mongoClient.RetrieveUserBindings(requestContext, &user)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user bindings")
			return types.User{}, fmt.Errorf("Error while retrieving user bindings: %s", err.Error())
		}

		userRolesIds := rolesIdsFromBindings(user.UserBindings)
		user.UserRoles, err = mongoClient.RetrieveUserRolesByRolesID(requestContext, userRolesIds)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user roles")

			return types.User{}, fmt.Errorf("Error while retrieving user Roles: %s", err.Error())
		}
	}
	return user, nil
}

func createRegoQueryInput(req *http.Request, env EnvironmentVariables, user types.User) ([]byte, error) {
	input := map[string]interface{}{
		"request": map[string]interface{}{
			"method":     req.Method,
			"path":       req.URL.Path,
			"headers":    req.Header,
			"query":      req.URL.Query(),
			"pathParams": mux.Vars(req),
		},
		"clientType": req.Header.Get(env.ClientTypeHeader),
	}

	userInput := make(map[string]interface{})
	userProperties := make(map[string]interface{})
	ok, err := unmarshalHeader(req.Header, env.UserPropertiesHeader, &userProperties)
	if err != nil {
		return nil, fmt.Errorf("user properties header is not valid: %s", err.Error())
	}
	if ok {
		userInput["properties"] = userProperties
	}

	userGroupsNotSplitted := req.Header.Get(env.UserGroupsHeader)
	if userGroupsNotSplitted != "" {
		userInput["groups"] = strings.Split(userGroupsNotSplitted, ",")
	}

	userInput["bindings"] = user.UserBindings
	userInput["roles"] = user.UserRoles
	input["user"] = userInput

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed input JSON encode: %v", err)
	}
	return inputBytes, nil
}

func unmarshalHeader(headers http.Header, headerKey string, v interface{}) (bool, error) {
	headerValueStringified := headers.Get(headerKey)
	if headerValueStringified != "" {
		if err := json.Unmarshal([]byte(headerValueStringified), &v); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
