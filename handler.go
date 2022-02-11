package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mongoclient"
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
		failResponse(w, "no policy permission found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	partialResultEvaluators, err := GetPartialResultsEvaluators(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no partialResult evaluators found in context")
		failResponse(w, "no partialResult evaluators found in context", GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if err := EvaluateRequest(req, env, w, partialResultEvaluators, permission); err != nil {
		return
	}
	ReverseProxy(logger, env, w, req, permission, partialResultEvaluators)
}

func EvaluateRequest(req *http.Request, env config.EnvironmentVariables, w http.ResponseWriter, partialResultsEvaluators PartialResultsEvaluators, permission *XPermission) error {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	userInfo, err := mongoclient.RetrieveUserBindingsAndRoles(logger, req, env)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		failResponseWithCode(w, http.StatusInternalServerError, "user bindings retrieval failed", GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	input, err := createRegoQueryInput(req, env, userInfo, nil)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed rego query input creation")
		failResponseWithCode(w, http.StatusInternalServerError, "RBAC input creation failed", GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	var evaluatorAllowPolicy *OPAEvaluator
	if !permission.ResourceFilter.RowFilter.Enabled {
		evaluatorAllowPolicy, err = partialResultsEvaluators.GetEvaluatorFromPolicy(requestContext, permission.AllowPermission, input)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot find policy evaluator")
			failResponseWithCode(w, http.StatusInternalServerError, "failed partial evaluator retrieval", GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	} else {
		evaluatorAllowPolicy, err = createQueryEvaluator(requestContext, logger, req, env, permission.AllowPermission, input, nil)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot create evaluator")
			failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluator creation failed", NO_PERMISSIONS_ERROR_MESSAGE)
			return err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(logger, permission)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && hasApplicationJSONContentType(req.Header) {
			w.WriteHeader(http.StatusOK)
			w.Header().Set(ContentTypeHeaderKey, JSONContentTypeHeader)
			w.Write([]byte("[]"))
			return err
		}

		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("RBAC policy evaluation failed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed", NO_PERMISSIONS_ERROR_MESSAGE)
		return err
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
			failResponseWithCode(w, http.StatusForbidden, "Error while marshaling row filter query", GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	}

	queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
	if permission.ResourceFilter.RowFilter.HeaderKey != "" {
		queryHeaderKey = permission.ResourceFilter.RowFilter.HeaderKey
	}
	if query != nil {
		req.Header.Set(queryHeaderKey, string(queryToProxy))
	}
	return nil
}

func ReverseProxy(logger *logrus.Entry, env config.EnvironmentVariables, w http.ResponseWriter, req *http.Request, permission *XPermission, partialResultsEvaluators PartialResultsEvaluators) {
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
		partialResultsEvaluators,
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
	ReverseProxy(logger, env, w, req, nil, nil)
}
