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
	"net/http"
	"strings"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
	rondlogrus "github.com/rond-authz/rond/logger/logrus"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

type OPAMiddlewareOptions struct {
	IsStandalone         bool
	PathPrefixStandalone string
}

func OPAMiddleware(
	opaModuleConfig *core.OPAModuleConfig,
	rondSDK sdk.OASEvaluatorFinder,
	routesToNotProxy []string,
	targetServiceOASPath string,
	options *OPAMiddlewareOptions,
) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if utils.Contains(routesToNotProxy, r.URL.RequestURI()) {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.EscapedPath()
			if options != nil && options.IsStandalone {
				path = strings.Replace(r.URL.EscapedPath(), options.PathPrefixStandalone, "", 1)
			}

			logger := glogger.Get(r.Context())

			evaluator, err := rondSDK.FindEvaluator(rondlogrus.NewEntry(logger), r.Method, path)
			rondConfig := core.RondConfig{}
			if err == nil {
				rondConfig = evaluator.Config()
			}

			if r.Method == http.MethodGet && r.URL.Path == targetServiceOASPath && rondConfig.RequestFlow.PolicyName == "" {
				fields := logrus.Fields{}
				if err != nil {
					fields["error"] = logrus.Fields{"message": err.Error()}
				}
				logger.WithFields(fields).Info("Proxying call to OAS Path even with no permission")
				next.ServeHTTP(w, r)
				return
			}

			if err != nil || rondConfig.RequestFlow.PolicyName == "" {
				errorMessage := "User is not allowed to request the API"
				statusCode := http.StatusForbidden
				fields := logrus.Fields{
					"originalRequestPath": utils.SanitizeString(r.URL.Path),
					"method":              utils.SanitizeString(r.Method),
					"allowPermission":     utils.SanitizeString(rondConfig.RequestFlow.PolicyName),
				}
				technicalError := ""
				if err != nil {
					technicalError = err.Error()
					fields["error"] = logrus.Fields{"message": err.Error()}
					errorMessage = "The request doesn't match any known API"
				}
				if errors.Is(err, openapi.ErrNotFoundOASDefinition) {
					statusCode = http.StatusNotFound
				}
				logger.WithFields(fields).Errorf(errorMessage)
				utils.FailResponseWithCode(w, statusCode, technicalError, errorMessage)
				return
			}

			ctx := sdk.WithEvaluator(r.Context(), evaluator)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
