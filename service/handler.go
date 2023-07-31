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
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/sdk"
	rondhttp "github.com/rond-authz/rond/sdk/rondinput/http"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"
const BASE_ROW_FILTER_HEADER_KEY = "acl_rows"

func ReverseProxyOrResponse(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	evaluatorSdk sdk.Evaluator,
) {
	var permission core.RondConfig
	if evaluatorSdk != nil {
		permission = evaluatorSdk.Config()
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
	ReverseProxy(logger, env, w, req, &permission, evaluatorSdk)
}

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogrus.FromContext(requestContext)

	env, err := config.GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		utils.FailResponse(w, "No environment found in context", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	evaluatorSdk, err := sdk.GetEvaluator(requestContext)
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
	evaluatorSdk sdk.Evaluator,
) error {
	logger := glogrus.FromContext(req.Context())

	permission := evaluatorSdk.Config()

	userInfo, err := mongoclient.RetrieveUserBindingsAndRoles(rondlogrus.NewEntry(logger), req, types.UserHeadersKeys{
		IDHeaderKey:         env.UserIdHeader,
		GroupsHeaderKey:     env.UserGroupsHeader,
		PropertiesHeaderKey: env.UserPropertiesHeader,
	})
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed user bindings and roles retrieving")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "user bindings retrieval failed", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}

	rondInput := rondhttp.NewInput(req, env.ClientTypeHeader, mux.Vars(req))
	result, err := evaluatorSdk.EvaluateRequestPolicy(req.Context(), rondInput, userInfo)
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
			"message": err.Error(),
		}).Error("RBAC policy evaluation failed")
		utils.FailResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed", utils.NO_PERMISSIONS_ERROR_MESSAGE)
		return err
	}

	queryHeaderKey := BASE_ROW_FILTER_HEADER_KEY
	if permission.RequestFlow.QueryOptions.HeaderName != "" {
		queryHeaderKey = permission.RequestFlow.QueryOptions.HeaderName
	}
	if result.QueryToProxy != nil {
		req.Header.Set(queryHeaderKey, string(result.QueryToProxy))
	}
	return nil
}

func ReverseProxy(
	logger *logrus.Entry,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	req *http.Request,
	permission *core.RondConfig,
	evaluatorSdk sdk.Evaluator,
) {
	targetHostFromEnv := env.TargetServiceHost
	u, err := url.Parse(fmt.Sprintf("%s://%s", URL_SCHEME, targetHostFromEnv))
	if err != nil {
		// FIXME: maybe better error handling?
		// targetHostFromEnv should not arrive here if
		// it's not a valid host to be put in a URL!
		panic(err)
	}

	proxy := httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.SetXForwarded()
		},
	}

	// Check on nil is performed to proxy the oas documentation path
	if permission == nil || permission.ResponseFlow.PolicyName == "" {
		proxy.ServeHTTP(w, req)
		return
	}
	proxy.Transport = NewOPATransport(
		http.DefaultTransport,
		req.Context(),
		logger,
		req,

		env.ClientTypeHeader,
		types.UserHeadersKeys{
			IDHeaderKey:         env.UserIdHeader,
			GroupsHeaderKey:     env.UserGroupsHeader,
			PropertiesHeaderKey: env.UserPropertiesHeader,
		},
		evaluatorSdk,
	)
	proxy.ServeHTTP(w, req)
}

func alwaysProxyHandler(w http.ResponseWriter, req *http.Request) {
	requestContext := req.Context()
	logger := glogrus.FromContext(req.Context())
	env, err := config.GetEnv(requestContext)
	if err != nil {
		logger.WithError(err).Error("no env found in context")
		utils.FailResponse(w, "no environment found in context", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, nil)
}
