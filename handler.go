package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httputil"

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

	opaEvaluator, err := GetOPAEvaluator(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no policy evaluator found in context")
		failResponse(w, "no policy evaluator found in context")
		return
	}

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
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("user properties header is not valid")
		failResponse(w, "User properties header is not valid")
		return
	}
	if ok {
		userInput["properties"] = userProperties
	}

	var userGroups []string
	ok, err = unmarshalHeader(req.Header, env.UserGroupsHeader, &userGroups)
	if err != nil {
		glogger.Get(req.Context()).WithField("error", logrus.Fields{"message": err.Error()}).Error("user group header is not valid")
		failResponse(w, "user group header is not valid")
		return
	}
	if ok {
		userInput["groups"] = userGroups
	}

	if len(userInput) != 0 {
		input["user"] = userInput
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
