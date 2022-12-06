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
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/utils"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

var (
	ErrRequestFailed  = errors.New("request failed")
	ErrFileLoadFailed = errors.New("file loading failed")
)

type OPAModuleConfigKey struct{}
type RouterInfoKey struct{}

type OPAModuleConfig struct {
	Name    string
	Content string
}

func OPAMiddleware(opaModuleConfig *OPAModuleConfig, openAPISpec *OpenAPISpec, envs *config.EnvironmentVariables, policyEvaluators PartialResultsEvaluators) mux.MiddlewareFunc {
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
				if errors.Is(err, ErrNotFoundOASDefinition) {
					statusCode = http.StatusNotFound
				}
				logger.WithFields(fields).Errorf(errorMessage)
				failResponseWithCode(w, statusCode, technicalError, errorMessage)
				return
			}

			ctx := WithXPermission(
				WithOPAModuleConfig(
					WithPartialResultsEvaluators(
						WithRouterInfo(logger, r.Context(), r),
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

func loadRegoModule(rootDirectory string) (*OPAModuleConfig, error) {
	var regoModulePath string
	//#nosec G104 -- Produces a false positive
	filepath.Walk(rootDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if regoModulePath != "" {
			return nil
		}

		if filepath.Ext(path) == ".rego" {
			regoModulePath = path
		}
		return nil
	})

	if regoModulePath == "" {
		return nil, fmt.Errorf("no rego module found in directory")
	}
	fileContent, err := readFile(regoModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed rego file read: %s", err.Error())
	}

	return &OPAModuleConfig{
		Name:    filepath.Base(regoModulePath),
		Content: string(fileContent),
	}, nil
}

func WithOPAModuleConfig(requestContext context.Context, permission *OPAModuleConfig) context.Context {
	return context.WithValue(requestContext, OPAModuleConfigKey{}, permission)
}

// GetOPAModuleConfig can be used by a request handler to get OPAModuleConfig instance from its context.
func GetOPAModuleConfig(requestContext context.Context) (*OPAModuleConfig, error) {
	permission, ok := requestContext.Value(OPAModuleConfigKey{}).(*OPAModuleConfig)
	if !ok {
		return nil, fmt.Errorf("no opa module config found in request context")
	}

	return permission, nil
}

type RouterInfo struct {
	MatchedPath   string
	RequestedPath string
	Method        string
}

func WithRouterInfo(logger *logrus.Entry, requestContext context.Context, req *http.Request) context.Context {
	pathTemplate := getPathTemplateOrDefaultToEmptyString(logger, req)
	return context.WithValue(requestContext, RouterInfoKey{}, RouterInfo{
		MatchedPath:   utils.SanitizeString(pathTemplate),
		RequestedPath: utils.SanitizeString(req.URL.Path),
		Method:        utils.SanitizeString(req.Method),
	})
}

func getPathTemplateOrDefaultToEmptyString(logger *logrus.Entry, req *http.Request) string {
	var pathTemplate string
	route := mux.CurrentRoute(req)
	if route != nil {
		var err error
		if pathTemplate, err = route.GetPathTemplate(); err != nil {
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("path template is empty")
			return ""
		}
	}
	return pathTemplate
}

func GetRouterInfo(requestContext context.Context) (RouterInfo, error) {
	routerInfo, ok := requestContext.Value(RouterInfoKey{}).(RouterInfo)
	if !ok {
		return RouterInfo{}, fmt.Errorf("no router info found")
	}
	return routerInfo, nil
}
