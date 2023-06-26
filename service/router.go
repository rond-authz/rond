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
	"context"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"

	swagger "github.com/davidebianchi/gswagger"
	"github.com/davidebianchi/gswagger/support/gorilla"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/helpers"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
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

func SetupRouter(
	log *logrus.Logger,
	env config.EnvironmentVariables,
	opaModuleConfig *core.OPAModuleConfig,
	oas *openapi.OpenAPISpec,
	sdk core.SDK,
	mongoClient *mongoclient.MongoClient,
	registry *prometheus.Registry,
) (*mux.Router, error) {
	router := mux.NewRouter().UseEncodedPath()
	router.Use(glogger.RequestMiddlewareLogger(log, []string{"/-/"}))
	serviceName := "rönd"
	StatusRoutes(router, serviceName, env.ServiceVersion)

	metrics.MetricsRoute(router, registry)

	router.Use(config.RequestMiddlewareEnvironments(env))

	evalRouter := router.NewRoute().Subrouter()
	if env.Standalone {
		router.Use(helpers.AddHeadersToProxyMiddleware(log, env.GetAdditionalHeadersToProxy()))

		swaggerRouter, err := swagger.NewRouter(gorilla.NewRouter(router), swagger.Options{
			Context: context.Background(),
			Openapi: &openapi3.T{
				Info: &openapi3.Info{
					Title:   serviceName,
					Version: env.ServiceVersion,
				},
			},
			JSONDocumentationPath: "/openapi/json",
			YAMLDocumentationPath: "/openapi/yaml",
		})
		if err != nil {
			return nil, err
		}

		// standalone routes
		if _, err := swaggerRouter.AddRoute(http.MethodPost, "/revoke/bindings/resource/{resourceType}", revokeHandler, revokeDefinitions); err != nil {
			return nil, err
		}
		if _, err := swaggerRouter.AddRoute(http.MethodPost, "/grant/bindings/resource/{resourceType}", grantHandler, grantDefinitions); err != nil {
			return nil, err
		}
		if _, err := swaggerRouter.AddRoute(http.MethodPost, "/revoke/bindings", revokeHandler, revokeDefinitions); err != nil {
			return nil, err
		}
		if _, err := swaggerRouter.AddRoute(http.MethodPost, "/grant/bindings", grantHandler, grantDefinitions); err != nil {
			return nil, err
		}

		if err = swaggerRouter.GenerateAndExposeOpenapi(); err != nil {
			return nil, err
		}
	}

	evalRouter.Use(core.OPAMiddleware(opaModuleConfig, sdk, routesToNotProxy, env.TargetServiceOASPath, &core.OPAMiddlewareOptions{
		IsStandalone:         env.Standalone,
		PathPrefixStandalone: env.PathPrefixStandalone,
	}))

	if mongoClient != nil {
		evalRouter.Use(mongoclient.MongoClientInjectorMiddleware(mongoClient))
	}

	setupRoutes(evalRouter, oas, env)

	//#nosec G104 -- Produces a false positive
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		log.Tracef("Registered path: %s", path)
		return nil
	})

	return router, nil
}

func setupRoutes(router *mux.Router, oas *openapi.OpenAPISpec, env config.EnvironmentVariables) {
	var documentationPermission string
	documentationPathInOAS := oas.Paths[env.TargetServiceOASPath]
	if documentationPathInOAS != nil {
		if getVerb, ok := documentationPathInOAS[strings.ToLower(http.MethodGet)]; ok && getVerb.PermissionV2 != nil {
			documentationPermission = getVerb.PermissionV2.RequestFlow.PolicyName
		}
	}

	paths, methodsMap, ignoreTrailingSlashMap := oas.UnwrapConfiguration()

	// NOTE: The following sort is required by mux router because it expects
	// routes to be registered in the proper order
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
			router.PathPrefix(openapi.ConvertPathVariablesToBrackets(pathWithoutAsterisk)).HandlerFunc(rbacHandler).Methods(methodsMap[path]...)
			continue
		}
		if path == env.TargetServiceOASPath && documentationPermission == "" {
			router.HandleFunc(openapi.ConvertPathVariablesToBrackets(pathToRegister), alwaysProxyHandler).Methods(http.MethodGet)
			continue
		}
		for _, method := range methodsMap[path] {
			actualPathToRegister := openapi.ConvertPathVariablesToBrackets(pathToRegister)
			shouldIgnoreTrailingSlash := ignoreTrailingSlashMap[path][method]
			if shouldIgnoreTrailingSlash {
				actualPathToRegister = fmt.Sprintf("/{%s:%s\\/?}", openapi.ConvertPathVariablesToBrackets(pathToRegister), openapi.ConvertPathVariablesToBrackets(pathToRegister))
			}
			router.HandleFunc(actualPathToRegister, rbacHandler).Methods(method)
		}
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
