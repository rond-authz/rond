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

package config

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mia-platform/configlib"
)

const (
	APIPermissionsFilePathEnvKey = "API_PERMISSIONS_FILE_PATH"
	TargetServiceOASPathEnvKey   = "TARGET_SERVICE_OAS_PATH"
	StandaloneEnvKey             = "STANDALONE"
	TargetServiceHostEnvKey      = "TARGET_SERVICE_HOST"
	BindingsCrudServiceURL       = "BINDINGS_CRUD_SERVICE_URL"

	TraceLogLevel = "trace"
)

// EnvironmentVariables struct with the mapping of desired
// environment variables.
type EnvironmentVariables struct {
	LogLevel                 string
	HTTPPort                 string
	ServiceVersion           string
	TargetServiceHost        string
	TargetServiceOASPath     string
	OPAModulesDirectory      string
	APIPermissionsFilePath   string
	UserPropertiesHeader     string
	UserGroupsHeader         string
	UserIdHeader             string
	ClientTypeHeader         string
	BindingsCrudServiceURL   string
	MongoDBUrl               string
	RolesCollectionName      string
	BindingsCollectionName   string
	PathPrefixStandalone     string
	DelayShutdownSeconds     int
	Standalone               bool
	AdditionalHeadersToProxy string
	ExposeMetrics            bool
}

var EnvVariablesConfig = []configlib.EnvConfig{
	{
		Key:          "LOG_LEVEL",
		Variable:     "LogLevel",
		DefaultValue: "info",
	},
	{
		Key:          "HTTP_PORT",
		Variable:     "HTTPPort",
		DefaultValue: "8080",
	},
	{
		Key:          "SERVICE_VERSION",
		Variable:     "ServiceVersion",
		DefaultValue: "latest",
	},
	{
		Key:      TargetServiceHostEnvKey,
		Variable: "TargetServiceHost",
	},
	{
		Key:      TargetServiceOASPathEnvKey,
		Variable: "TargetServiceOASPath",
	},
	{
		Key:      "OPA_MODULES_DIRECTORY",
		Variable: "OPAModulesDirectory",
		Required: true,
	},
	{
		Key:      APIPermissionsFilePathEnvKey,
		Variable: "APIPermissionsFilePath",
	},
	{
		Key:          "USER_PROPERTIES_HEADER_KEY",
		Variable:     "UserPropertiesHeader",
		DefaultValue: "miauserproperties",
	},
	{
		Key:          "USER_GROUPS_HEADER_KEY",
		Variable:     "UserGroupsHeader",
		DefaultValue: "miausergroups",
	},
	{
		Key:          "USER_ID_HEADER_KEY",
		Variable:     "UserIdHeader",
		DefaultValue: "miauserid",
	},
	{
		Key:          "CLIENT_TYPE_HEADER_KEY",
		Variable:     "ClientTypeHeader",
		DefaultValue: "Client-Type",
	},
	{
		Key:          "DELAY_SHUTDOWN_SECONDS",
		Variable:     "DelayShutdownSeconds",
		DefaultValue: "10",
	},
	{
		Key:      "MONGODB_URL",
		Variable: "MongoDBUrl",
	},
	{
		Key:      "BINDINGS_COLLECTION_NAME",
		Variable: "BindingsCollectionName",
	},
	{
		Key:      "ROLES_COLLECTION_NAME",
		Variable: "RolesCollectionName",
	},
	{
		Key:      StandaloneEnvKey,
		Variable: "Standalone",
	},
	{
		Key:          "PATH_PREFIX_STANDALONE",
		Variable:     "PathPrefixStandalone",
		DefaultValue: "/eval",
	},
	{
		Key:      BindingsCrudServiceURL,
		Variable: "BindingsCrudServiceURL",
	},
	{
		Key:          "ADDITIONAL_HEADERS_TO_PROXY",
		Variable:     "AdditionalHeadersToProxy",
		DefaultValue: "miauserid",
	},
	{
		Key:          "EXPOSE_METRICS",
		Variable:     "ExposeMetrics",
		DefaultValue: "true",
	},
}

type EnvKey struct{}

// RequestMiddlewareEnvironments is a gorilla/mux middleware used to inject
// env variables into requests.
func RequestMiddlewareEnvironments(env EnvironmentVariables) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), EnvKey{}, env)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetEnv can be used by a request handler to get environment variables from its context.
func GetEnv(requestContext context.Context) (EnvironmentVariables, error) {
	env, ok := requestContext.Value(EnvKey{}).(EnvironmentVariables)
	if !ok {
		return EnvironmentVariables{}, fmt.Errorf("no environment in request context")
	}

	return env, nil
}

func GetEnvOrDie() EnvironmentVariables {
	var env EnvironmentVariables
	if err := configlib.GetEnvVariables(EnvVariablesConfig, &env); err != nil {
		panic(err.Error())
	}

	if env.TargetServiceHost == "" && !env.Standalone {
		panic(fmt.Errorf("missing environment variables, one of %s or %s set to true is required", TargetServiceHostEnvKey, StandaloneEnvKey))
	}

	if env.Standalone && env.BindingsCrudServiceURL == "" {
		panic(fmt.Errorf("missing environment variables, %s must be set if mode is standalone", BindingsCrudServiceURL))
	}

	return env
}

var extraHeadersKeys = []string{"x-request-id", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"}

func (env EnvironmentVariables) GetAdditionalHeadersToProxy() []string {
	if env.AdditionalHeadersToProxy == "" {
		return extraHeadersKeys
	}
	customHeaders := strings.Split(env.AdditionalHeadersToProxy, ",")
	for _, extraHeaderKey := range extraHeadersKeys {
		duplicate := false
		for _, customHeader := range customHeaders {
			if customHeader == extraHeaderKey {
				duplicate = true
				break
			}
		}
		if !duplicate {
			customHeaders = append(customHeaders, extraHeaderKey)
		}
	}
	return customHeaders
}
