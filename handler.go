package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"rbac-service/internal/types"
	"rbac-service/internal/utils"

	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"

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

	if mongoClient != nil {
		var user types.User
		userBindings = make([]types.Binding, 0)
		userRoles = make([]types.Role, 0)

		user.UserGroups = strings.Split(req.Header.Get(env.UserGroupsHeader), ",")
		user.UserID = req.Header.Get(env.UserIdHeader)

		if user.UserID == "" {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": "User unknown"}).Error("User is unknown")
			failResponseWithCode(w, http.StatusForbidden, "Error while retrieving user permissions: user is unknown")
			return
		}

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

	evaluator, err := NewOPAEvaluator(permission.AllowPermission, opaModuleConfig)
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("failed RBAC policy creation")
		failResponse(w, err.Error())
		return
	}

	// TODO: opaEvaluator.PermissionQuery.Partial(context.TODO())
	results, err := evaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("policy eval failed")
		failResponse(w, "policy eval failed")
		return
	}

	glogger.Get(req.Context()).WithFields(logrus.Fields{
		"allowed":       results.Allowed(),
		"resultsLength": len(results),
	}).Tracef("policy results")

	if !results.Allowed() {
		glogger.Get(req.Context()).Error("policy resulted in not allowed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed")
		return
	}

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

func createRegoQueryInput(req *http.Request, env EnvironmentVariables, userBindings []types.Binding, userRoles []types.Role) (map[string]interface{}, error) {
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

	return input, nil
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
