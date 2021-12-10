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
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("unexpected MongoDB client found in context")
		failResponse(w, "Unexpected error retrieving MongoDB Client from request context")
		return
	}

	opaEvaluator, err := GetOPAEvaluator(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no policy evaluator found in context")
		failResponse(w, "no policy evaluator found in context")
		return
	}

	if mongoClient != nil {
		var user types.User

		user.UserGroups = strings.Split(req.Header.Get(env.UserGroupsHeader), ",")
		user.UserID = req.Header.Get(env.UserIdHeader)

		if user.UserID == "" {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": "User unknown"}).Error("User is unknown")
			failResponseWithCode(w, http.StatusForbidden, "Error while retrieving user permissions: user is unknown")
			return
		}

		userPermissions, err := mongoClient.FindUserPermissions(req.Context(), &user)
		if err != nil {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("something went wrong while retrieving user permissions")
			failResponse(w, fmt.Sprintf("Error while retrieving user permissions: %s", err.Error()))
			return
		}

		permission := opaEvaluator.RequiredAllowPermission
		if !utils.Contains(userPermissions, permission) {
			glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": "User is not allowed"}).Error("User is not allowed")
			failResponseWithCode(w, http.StatusForbidden, "Error while retrieving user permissions: user is not allowed")
			return
		}
	}

	input, err := createRegoQueryInput(req, env)
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("user properties header is not valid")
		failResponse(w, fmt.Sprintf("Failed rego query input creation: %s", err.Error()))
		return
	}

	results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
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

func createRegoQueryInput(req *http.Request, env EnvironmentVariables) (map[string]interface{}, error) {
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
