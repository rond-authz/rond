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

package main

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	swagger "github.com/davidebianchi/gswagger"
	"github.com/mia-platform/glogger/v2"
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

var routesToNotProxy = utils.Union(statusRoutes, []string{metrics.MetricsRoutePath})

var revokeDefinitions = swagger.Definitions{
	RequestBody: &swagger.ContentValue{
		Content: swagger.Content{
			"application/json": {
				Value: RevokeRequestBody{},
			},
		},
	},
	Responses: map[int]swagger.ContentValue{
		http.StatusOK: {
			Content: swagger.Content{
				"application/json": {Value: RevokeResponseBody{}},
			},
		},
		http.StatusInternalServerError: {
			Content: swagger.Content{
				"application/json": {Value: types.RequestError{}},
			},
		},
		http.StatusBadRequest: {
			Content: swagger.Content{
				"application/json": {Value: types.RequestError{}},
			},
		},
	},
}

var grantDefinitions = swagger.Definitions{
	RequestBody: &swagger.ContentValue{
		Content: swagger.Content{
			"application/json": {
				Value: GrantRequestBody{},
			},
		},
	},
	Responses: map[int]swagger.ContentValue{
		http.StatusOK: {
			Content: swagger.Content{
				"application/json": {Value: GrantResponseBody{}},
			},
		},
		http.StatusInternalServerError: {
			Content: swagger.Content{
				"application/json": {Value: types.RequestError{}},
			},
		},
		http.StatusBadRequest: {
			Content: swagger.Content{
				"application/json": {Value: types.RequestError{}},
			},
		},
	},
}

func addStandaloneRoutes(router *swagger.Router) error {
	if _, err := router.AddRoute(http.MethodPost, "/revoke/bindings/resource/{resourceType}", revokeHandler, revokeDefinitions); err != nil {
		return err
	}
	if _, err := router.AddRoute(http.MethodPost, "/grant/bindings/resource/{resourceType}", grantHandler, grantDefinitions); err != nil {
		return err
	}
	if _, err := router.AddRoute(http.MethodPost, "/revoke/bindings", revokeHandler, revokeDefinitions); err != nil {
		return err
	}
	if _, err := router.AddRoute(http.MethodPost, "/grant/bindings", grantHandler, grantDefinitions); err != nil {
		return err
	}
	return nil
}

func setupRoutes(router *mux.Router, oas *openapi.OpenAPISpec, env config.EnvironmentVariables) {
	var documentationPermission string
	documentationPathInOAS := oas.Paths[env.TargetServiceOASPath]
	if documentationPathInOAS != nil {
		if getVerb, ok := documentationPathInOAS[strings.ToLower(http.MethodGet)]; ok && getVerb.PermissionV2 != nil {
			documentationPermission = getVerb.PermissionV2.RequestFlow.PolicyName
		}
	}

	// NOTE: The following sort is required by mux router because it expects
	// routes to be registered in the proper order
	paths := make([]string, 0)
	methods := make(map[string][]string, 0)

	for path, pathMethods := range oas.Paths {
		paths = append(paths, path)
		for method := range pathMethods {
			if method == openapi.AllHTTPMethod {
				methods[path] = openapi.OasSupportedHTTPMethods
				continue
			}
			if methods[path] == nil {
				methods[path] = []string{}
			}

			methods[path] = append(methods[path], strings.ToUpper(method))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))

	for _, path := range paths {
		pathToRegister := path
		if env.Standalone {
			pathToRegister = fmt.Sprintf("%s%s", env.PathPrefixStandalone, path)
		}
		if utils.Contains(routesToNotProxy, pathToRegister) {
			continue
		}
		if strings.Contains(pathToRegister, "*") {
			pathWithoutAsterisk := strings.ReplaceAll(pathToRegister, "*", "")
			router.PathPrefix(openapi.ConvertPathVariablesToBrackets(pathWithoutAsterisk)).HandlerFunc(rbacHandler).Methods(methods[path]...)
			continue
		}
		if path == env.TargetServiceOASPath && documentationPermission == "" {
			router.HandleFunc(openapi.ConvertPathVariablesToBrackets(pathToRegister), alwaysProxyHandler).Methods(http.MethodGet)
			continue
		}
		router.HandleFunc(openapi.ConvertPathVariablesToBrackets(pathToRegister), rbacHandler).Methods(methods[path]...)
	}
	if documentationPathInOAS == nil {
		router.HandleFunc(openapi.ConvertPathVariablesToBrackets(env.TargetServiceOASPath), alwaysProxyHandler)
	}
	// FIXME: All the routes don't inserted above are anyway handled by rbacHandler.
	//        Maybe the code above can be cleaned.
	// NOTE: this fallback route should be removed in v2, check out
	// 			 issue [14](https://github.com/rond-authz/rond/issues/14) for further details.
	fallbackRoute := "/"
	if env.Standalone {
		fallbackRoute = fmt.Sprintf("%s/", path.Join(env.PathPrefixStandalone, fallbackRoute))
	}
	router.PathPrefix(fallbackRoute).HandlerFunc(rbacHandler)
}

func OPAMiddleware(opaModuleConfig *core.OPAModuleConfig, openAPISpec *openapi.OpenAPISpec, envs *config.EnvironmentVariables, policyEvaluators core.PartialResultsEvaluators) mux.MiddlewareFunc {
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
				failResponseWithCode(w, statusCode, technicalError, errorMessage)
				return
			}

			ctx := openapi.WithXPermission(
				core.WithOPAModuleConfig(
					core.WithPartialResultsEvaluators(
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
