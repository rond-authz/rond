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
	"strings"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/sdk"
	"github.com/rond-authz/rond/sdk/inputuser"
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
	inputUser core.InputUser,
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
	ReverseProxy(logger, env, w, req, &permission, evaluatorSdk, inputUser)
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

	rondInputUser, err := getInputUser(logger, env, req)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed to get input user")
		utils.FailResponse(w, "failed to get input user", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return
	}

	if err := EvaluateRequest(req, env, w, evaluatorSdk, rondInputUser); err != nil {
		return
	}
	ReverseProxyOrResponse(logger, env, w, req, evaluatorSdk, rondInputUser)
}

func EvaluateRequest(
	req *http.Request,
	env config.EnvironmentVariables,
	w http.ResponseWriter,
	evaluatorSdk sdk.Evaluator,
	rondInputUser core.InputUser,
) error {
	logger := glogrus.FromContext(req.Context())

	permission := evaluatorSdk.Config()

	rondInput, err := rondhttp.NewInput(req, env.ClientTypeHeader, mux.Vars(req), rondInputUser, nil)
	if err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed to create rond input")
		utils.FailResponseWithCode(w, http.StatusInternalServerError, "failed to create rond input", utils.GENERIC_BUSINESS_ERROR_MESSAGE)
		return err
	}
	result, err := evaluatorSdk.EvaluateRequestPolicy(req.Context(), rondInput, &sdk.EvaluateOptions{
		Logger: rondlogrus.NewEntry(logger),
	})
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
	// FIXME: header is always set, also if query to proxy is empty
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
	inputUser core.InputUser,
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
		inputUser,
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
	ReverseProxyOrResponse(logger, env, w, req, nil, core.InputUser{})
}

type userHeadersKeys struct {
	GroupsHeaderKey     string
	IDHeaderKey         string
	PropertiesHeaderKey string
}

func getUserFromRequest(req *http.Request, userHeaders userHeadersKeys) (types.User, error) {
	var user types.User

	user.Groups = split(req.Header.Get(userHeaders.GroupsHeaderKey), ",")
	user.ID = req.Header.Get(userHeaders.IDHeaderKey)

	userProperties := make(map[string]interface{})
	_, err := utils.UnmarshalHeader(req.Header, userHeaders.PropertiesHeaderKey, &userProperties)
	if err != nil {
		return types.User{}, fmt.Errorf("user properties header is not valid: %s", err.Error())
	}
	user.Properties = userProperties

	return user, nil
}

func getInputUser(logger *logrus.Entry, env config.EnvironmentVariables, req *http.Request) (core.InputUser, error) {
	user, err := getUserFromRequest(req, userHeadersKeys{
		IDHeaderKey:         env.UserIdHeader,
		GroupsHeaderKey:     env.UserGroupsHeader,
		PropertiesHeaderKey: env.UserPropertiesHeader,
	})
	if err != nil {
		return core.InputUser{}, fmt.Errorf("fails to get user from request: %s", err)
	}

	client, err := inputuser.GetClientFromContext(req.Context())
	if err != nil {
		return core.InputUser{}, err
	}

	rondInputUser, err := inputuser.GetInputUser(req.Context(), rondlogrus.NewEntry(logger), client, user)
	if err != nil {
		return core.InputUser{}, err
	}

	return rondInputUser, nil
}

func split(str, sep string) []string {
	if str == "" {
		return []string{}
	}
	return strings.Split(str, sep)
}
