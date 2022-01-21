package main

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"

	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"
const GENERIC_BUSINESS_ERROR_MESSAGE = "Internal server error, please try again later"
const NO_PERMISSIONS_ERROR_MESSAGE = "You do not have permissions to access this feature, contact the project administrator for more information."

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	env, err := GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		failResponse(w, "No environment found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	permission, err := GetXPermission(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no policy permission found in context")
		failResponse(w, "No policy permission found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	evaluator, err := createEvaluator(logger, req, w, env, permission)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		failResponse(w, "Failed RBAC policy creation", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	query, err := evaluator.PolicyEvaluation(logger, permission)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("RBAC policy evaluation failed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed", NO_PERMISSIONS_ERROR_MESSAGE)
		return
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
			failResponseWithCode(w, http.StatusForbidden, "Error while marshaling row filter query", GENERIC_BUSINESS_ERROR_MESSAGE)
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
	opaWriter := NewOpaResponseWriter(w)
	proxy.ServeHTTP(opaWriter, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	env, err := GetEnv(requestContext)
	if err != nil {
		glogger.Get(requestContext).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	ReverseProxy(env, w, req)
}
