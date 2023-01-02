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

package core

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

func OPAMiddleware(
	opaModuleConfig *OPAModuleConfig,
	openAPISpec *openapi.OpenAPISpec,
	envs *config.EnvironmentVariables,
	policyEvaluators PartialResultsEvaluators,
	routesToNotProxy []string,
) mux.MiddlewareFunc {
	OASrouter := openAPISpec.PrepareOASRouter()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if utils.Contains(routesToNotProxy, r.URL.RequestURI()) {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.EscapedPath()
			if envs.Standalone {
				path = strings.Replace(r.URL.EscapedPath(), envs.PathPrefixStandalone, "", 1)
			}

			logger := glogger.Get(r.Context())

			permission, err := openAPISpec.FindPermission(OASrouter, path, r.Method)
			if r.Method == http.MethodGet && r.URL.Path == envs.TargetServiceOASPath && permission.RequestFlow.PolicyName == "" {
				fields := logrus.Fields{}
				if err != nil {
					fields["error"] = logrus.Fields{"message": err.Error()}
				}
				logger.WithFields(fields).Info("Proxying call to OAS Path even with no permission")
				next.ServeHTTP(w, r)
				return
			}

			if err != nil || permission.RequestFlow.PolicyName == "" {
				errorMessage := "User is not allowed to request the API"
				statusCode := http.StatusForbidden
				fields := logrus.Fields{
					"originalRequestPath": utils.SanitizeString(r.URL.Path),
					"method":              utils.SanitizeString(r.Method),
					"allowPermission":     utils.SanitizeString(permission.RequestFlow.PolicyName),
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

			ctx := openapi.WithXPermission(
				WithOPAModuleConfig(
					WithPartialResultsEvaluators(
						openapi.WithRouterInfo(logger, r.Context(), r),
						policyEvaluators,
					),
					opaModuleConfig,
				),
				&permission,
			)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
