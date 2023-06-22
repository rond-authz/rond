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

package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"

func ReverseProxyOrResponse(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	evaluatorSdk core.SDKEvaluator,
) {
	var permission openapi.RondConfig
	var partialResultsEvaluators core.PartialResultsEvaluators
	if evaluatorSdk != nil {
		permission = evaluatorSdk.Config()
		partialResultsEvaluators = evaluatorSdk.PartialResultsEvaluators()
	}

	if env.Standalone {
		if permission.RequestFlow.GenerateQuery {
			queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
			if permission.RequestFlow.QueryOptions.HeaderName != "" {
				queryHeaderKey = permission.RequestFlow.QueryOptions.HeaderName
			}
			securityQuery := req.Header.Get(queryHeaderKey)
			w.Header().Set(queryHeaderKey, securityQuery)
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(nil); err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
		}
		return
	}
	ReverseProxy(logger, env, w, req, &permission, partialResultsEvaluators)
}

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	env, err := config.GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		utils.FailResponse(w, "No environment found in context", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	evaluatorSdk, err := core.GetEvaluatorSKD(requestContext)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("no evaluatorSdk found in context")
		utils.FailResponse(w, "no evaluators sdk found in context", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if err := EvaluateRequest(req, env, w, evaluatorSdk); err != nil {
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, evaluatorSdk)
}

func EvaluateRequest(
	req *http.Request,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	evaluatorSdk core.SDKEvaluator,
) error {
	requestContext := req.Context()
	logger := glogger.Get(requestContext)

	permission := evaluatorSdk.Config()
	partialResultsEvaluators := evaluatorSdk.PartialResultsEvaluators()

	userInfo, err := mongoclient.RetrieveUserBindingsAndRoles(logger, req, types.UserHeadersKeys{
		IDHeaderKey:         env.UserIdHeader,
		GroupsHeaderKey:     env.UserGroupsHeader,
		PropertiesHeaderKey: env.UserPropertiesHeader,
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "user bindings retrieval failed", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	pathParams := mux.Vars(req)
	rondReq := core.NewRondInput(req, env.ClientTypeHeader, pathParams)
	input, err := rondReq.FromRequestInfo(userInfo, nil)
	if err != nil {
		return err
	}

	regoInput, err := core.CreateRegoQueryInput(logger, input, core.RegoInputOptions{
		EnableResourcePermissionsMapOptimization: permission.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed rego query input creation")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "RBAC input creation failed", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	evaluatorOptions := &core.EvaluatorOptions{
		EnablePrintStatements: env.IsTraceLogLevel(),
	}

	var evaluatorAllowPolicy *core.OPAEvaluator
	if !permission.RequestFlow.GenerateQuery {
		evaluatorAllowPolicy, err = partialResultsEvaluators.GetEvaluatorFromPolicy(requestContext, permission.RequestFlow.PolicyName, regoInput, evaluatorOptions)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot find policy evaluator")
			utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed partial evaluator retrieval", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	} else {
		evaluatorAllowPolicy, err = core.CreateQueryEvaluator(requestContext, logger, req, permission.RequestFlow.PolicyName, regoInput, nil, evaluatorOptions)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("cannot create evaluator")
			utils.FailResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluator creation failed", utils.NO_PERMISSIONS_ERROR_MESSAGE)
			return err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(logger, &permission)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && utils.HasApplicationJSONContentType(req.Header) {
			w.Header().Set(utils.ContentTypeHeaderKey, utils.JSONContentTypeHeader)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("[]")); err != nil {
				logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
				return err
			}
			return err
		}

		logger.WithField("error", logrus.Fields{
			"policyName": permission.RequestFlow.PolicyName,
			"message":    err.Error(),
		}).Error("RBAC policy evaluation failed")
		utils.FailResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed", utils.NO_PERMISSIONS_ERROR_MESSAGE)
		return err
	}
	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("Error while marshaling row filter query")
			utils.FailResponseWithCode(w, http.StatusForbidden, "Error while marshaling row filter query", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
			return err
		}
	}

	queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
	if permission.RequestFlow.QueryOptions.HeaderName != "" {
		queryHeaderKey = permission.RequestFlow.QueryOptions.HeaderName
	}
	if query != nil {
		req.Header.Set(queryHeaderKey, string(queryToProxy))
	}
	return nil
}

func ReverseProxy(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	permission *openapi.RondConfig,
	partialResultsEvaluators core.PartialResultsEvaluators,
) {
	targetHostFromEnv := env.TargetServiceHost
	proxy := httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(req *http.Request) {
			req.URL.Host = targetHostFromEnv
			req.URL.Scheme = URL_SCHEME
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Del("User-Agent")
			}
		},
	}

	options := &core.EvaluatorOptions{
		EnablePrintStatements: env.IsTraceLogLevel(),
	}

	// Check on nil is performed to proxy the oas documentation path
	if permission == nil || permission.ResponseFlow.PolicyName == "" {
		proxy.ServeHTTP(w, req)
		return
	}
	proxy.Transport = core.NewOPATransport(
		http.DefaultTransport,
		req.Context(),
		logger,
		req,
		permission,
		partialResultsEvaluators,

		env.ClientTypeHeader,
		types.UserHeadersKeys{
			IDHeaderKey:         env.UserIdHeader,
			GroupsHeaderKey:     env.UserGroupsHeader,
			PropertiesHeaderKey: env.UserPropertiesHeader,
		},
		options,
	)
	proxy.ServeHTTP(w, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogger.Get(req.Context())
	env, err := config.GetEnv(requestContext)
	if err != nil {
		glogger.Get(requestContext).WithError(err).Error("no env found in context")
		utils.FailResponse(w, "no environment found in context", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, nil)
}
