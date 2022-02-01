package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/opatranslator"

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

	env, err := config.GetEnv(requestContext)
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

	evaluator, err := createEvaluator(requestContext, logger, req, env, permission.AllowPermission, nil)
	if err != nil {
		logger.WithError(err).Error("failed RBAC policy creation")
		failResponse(w, "Failed RBAC policy creation", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	_, query, err := evaluator.PolicyEvaluation(logger, permission)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && hasApplicationJSONContentType(req.Header) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}

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
	ReverseProxy(logger, env, w, req, permission)
}

func ReverseProxy(logger *logrus.Entry, env config.EnvironmentVariables, w http.ResponseWriter, req *http.Request, permission *XPermission) {
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
	// Check on nil is performed to proxy the oas documentation path
	if permission == nil || permission.ResponseFilter.Policy == "" {
		proxy.ServeHTTP(w, req)
		return
	}
	proxy.Transport = &OPATransport{
		http.DefaultTransport,
		req.Context(),
		logger,
		req,
		env,
		permission,
	}
	proxy.ServeHTTP(w, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(req.Context())
	env, err := config.GetEnv(requestContext)
	if err != nil {
		glogger.Get(requestContext).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	ReverseProxy(logger, env, w, req, nil)
}
