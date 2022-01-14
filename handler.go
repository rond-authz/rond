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

	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	env, err := GetEnv(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context")
		return
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

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	env, err := GetEnv(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context")
		return
	}

	mongoClient, err := GetMongoClientFromContext(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("unexpected MongoDB client not found in context")
		failResponse(w, "Unexpected error retrieving MongoDB Client from request context")
		return
	}

	permission, err := GetXPermission(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("no policy permission found in context")
		failResponse(w, "no policy permission found in context")
		return
	}

	opaModuleConfig, err := GetOPAModuleConfig(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("no OPA module configuration found in context")
		failResponse(w, "no OPA module configuration found in context")
		return
	}

	var userBindings []types.Binding
	var userRoles []types.Role
	var user types.User
	userBindings = make([]types.Binding, 0)
	userRoles = make([]types.Role, 0)

	user.UserGroups = strings.Split(req.Header.Get(env.UserGroupsHeader), ",")
	user.UserID = req.Header.Get(env.UserIdHeader)

	if mongoClient != nil && user.UserID != "" {

		userBindings, err = mongoClient.RetrieveUserBindings(req.Context(), &user)
		if err != nil {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user bindings")
			failResponse(w, fmt.Sprintf("Error while retrieving user bindings: %s", err.Error()))
			return
		}

		userRolesIds := rolesIdsFromBindings(userBindings)
		userRoles, err = mongoClient.RetrieveUserRolesByRolesID(req.Context(), userRolesIds)
		if err != nil {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user roles")
			failResponse(w, fmt.Sprintf("Error while retrieving user roles: %s", err.Error()))
			return
		}
	}
	input, err := createRegoQueryInput(req, env, userBindings, userRoles)
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("user properties header is not valid")
		failResponse(w, fmt.Sprintf("Failed rego query input creation: %s", err.Error()))
		return
	}

	glogger.Get(req.Context()).WithFields(logrus.Fields{
		"input": string(input),
	}).Trace("input object passed to the evaluator")

	evaluator, err := NewOPAEvaluator(permission.AllowPermission, opaModuleConfig, input)
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("failed RBAC policy creation")
		failResponse(w, err.Error())
		return
	}

	_, query, err := Evaluate(permission, *evaluator, req)
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("RBAC policy evaluation failed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed")
		return
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
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

func Evaluate(permission *XPermission, evaluator OPAEvaluator, req *http.Request) (bool, primitive.M, error) {
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
		glogger.Get(req.Context()).WithFields(logrus.Fields{
			"allowed": true,
			"query":   q,
		}).Tracef("policy results and query")
		return true, q, nil
	}

	results, err := evaluator.PermissionQuery.Eval(context.TODO())
	if err != nil {
		return false, nil, fmt.Errorf("Policy Evaluation has failed when evaluating the query: %s", err.Error())
	}

	glogger.Get(req.Context()).WithFields(logrus.Fields{
		"allowed":       results.Allowed(),
		"resultsLength": len(results),
	}).Tracef("policy results")

	if !results.Allowed() {
		glogger.Get(req.Context()).Error("policy resulted in not allowed")
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

func createRegoQueryInput(req *http.Request, env EnvironmentVariables, userBindings []types.Binding, userRoles []types.Role) ([]byte, error) {
	input := map[string]interface{}{
		"request": map[string]interface{}{
			"method":  req.Method,
			"path":    req.URL.Path,
			"headers": req.Header,
			"query":   req.URL.Query(),
		},
		"clientType": req.Header.Get(env.ClientTypeHeader),
	}

	userInput := make(map[string]interface{})
	userProperties := make(map[string]interface{})
	ok, err := unmarshalHeader(req.Header, env.UserPropertiesHeader, &userProperties)
	if err != nil {
		return nil, fmt.Errorf("User properties header is not valid: %s", err.Error())
	}
	if ok {
		userInput["properties"] = userProperties
	}

	userGroupsNotSplitted := req.Header.Get(env.UserGroupsHeader)
	if userGroupsNotSplitted != "" {
		userInput["groups"] = strings.Split(userGroupsNotSplitted, ",")
	}
	if len(userBindings) != 0 {
		userInput["bindings"] = userBindings
	}
	if len(userRoles) != 0 {
		userInput["roles"] = userRoles
	}

	if len(userInput) != 0 {
		input["user"] = userInput
	}
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
