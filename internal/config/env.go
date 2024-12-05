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

	envlib "github.com/caarlos0/env/v11"
	"github.com/gorilla/mux"
)

const (
	apiPermissionsFilePathEnvKey = "API_PERMISSIONS_FILE_PATH"
	targetServiceOASPathEnvKey   = "TARGET_SERVICE_OAS_PATH"
	standaloneEnvKey             = "STANDALONE"
	targetServiceHostEnvKey      = "TARGET_SERVICE_HOST"
	bindingsCrudServiceURL       = "BINDINGS_CRUD_SERVICE_URL"

	traceLogLevel = "trace"
)

// EnvironmentVariables struct with the mapping of desired
// environment variables.
type EnvironmentVariables struct {
	LogLevel                       string `env:"LOG_LEVEL" envDefault:"info"`
	HTTPPort                       string `env:"HTTP_PORT" envDefault:"8080"`
	ServiceVersion                 string `env:"SERVICE_VERSION" envDefault:"latest"`
	TargetServiceHost              string `env:"TARGET_SERVICE_HOST"`
	TargetServiceOASPath           string `env:"TARGET_SERVICE_OAS_PATH"`
	OPAModulesDirectory            string `env:"OPA_MODULES_DIRECTORY,required"`
	APIPermissionsFilePath         string `env:"API_PERMISSIONS_FILE_PATH"`
	UserPropertiesHeader           string `env:"USER_PROPERTIES_HEADER_KEY" envDefault:"miauserproperties"`
	UserGroupsHeader               string `env:"USER_GROUPS_HEADER_KEY" envDefault:"miausergroups"`
	UserIdHeader                   string `env:"USER_ID_HEADER_KEY" envDefault:"miauserid"`
	ClientTypeHeader               string `env:"CLIENT_TYPE_HEADER_KEY" envDefault:"Client-Type"`
	BindingsCrudServiceURL         string `env:"BINDINGS_CRUD_SERVICE_URL"`
	MongoDBUrl                     string `env:"MONGODB_URL"`
	MongoDBConnectionMaxIdleTimeMs int    `env:"MONGODB_CONNECTION_MAX_IDLE_TIME_MS" envDefault:"1000"`
	RolesCollectionName            string `env:"ROLES_COLLECTION_NAME"`
	BindingsCollectionName         string `env:"BINDINGS_COLLECTION_NAME"`
	PathPrefixStandalone           string `env:"PATH_PREFIX_STANDALONE" envDefault:"/eval"`
	DelayShutdownSeconds           int    `env:"DELAY_SHUTDOWN_SECONDS" envDefault:"10"`
	Standalone                     bool   `env:"STANDALONE"`
	AdditionalHeadersToProxy       string `env:"ADDITIONAL_HEADERS_TO_PROXY" envDefault:"miauserid"`
	ExposeMetrics                  bool   `env:"EXPOSE_METRICS" envDefault:"true"`
	EnableAuditTrail               bool   `env:"ENABLE_AUDIT_TRAIL"`
	AuditAggregationIDHeaderName   string `env:"AUDIT_AGGREGATION_ID_HEADER_NAME" envDefault:"x-request-id"`
	AuditTargetServiceName         string `env:"TARGET_SERVICE_NAME"`
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
	env, err := envlib.ParseAs[EnvironmentVariables]()
	if err != nil {
		panic(err.Error())
	}

	if env.TargetServiceHost == "" && !env.Standalone {
		panic(fmt.Errorf("missing environment variables, one of %s or %s set to true is required", targetServiceHostEnvKey, standaloneEnvKey))
	}

	if env.Standalone && env.BindingsCrudServiceURL == "" {
		panic(fmt.Errorf("missing environment variables, %s must be set if mode is standalone", bindingsCrudServiceURL))
	}

	if env.APIPermissionsFilePath == "" && env.TargetServiceOASPath == "" {
		panic(fmt.Errorf("missing environment variables, one of %s or %s is required", apiPermissionsFilePathEnvKey, targetServiceOASPathEnvKey))
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

func (env EnvironmentVariables) IsTraceLogLevel() bool {
	return env.LogLevel == traceLogLevel
}
