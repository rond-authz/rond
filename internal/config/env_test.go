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
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestMiddlewareEnvironments(t *testing.T) {
	t.Run(`RequestMiddlewareEnvironments properly sets env variables into request context`, func(t *testing.T) {
		middleware := RequestMiddlewareEnvironments(EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})

		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			env, ok := r.Context().Value(EnvKey{}).(EnvironmentVariables)
			require.True(t, ok, "Unexpected type in context.")
			require.Equal(t, "localhost:3000", env.TargetServiceHost, "Unexpected session duration seconds env variable.")
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		builtHandler.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code.")
	})
}

func TestGetEnv(t *testing.T) {
	t.Run(`GetEnv fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetEnv(ctx)
		require.Error(t, err, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetEnv returns EnvVariables from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), EnvKey{}, EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})
		env, err := GetEnv(ctx)
		require.NoError(t, err, "Unexpected error.")
		require.Equal(t, "localhost:3000", env.TargetServiceHost, "Unexpected session duration seconds env variable.")
	})
}

func TestGetEnvOrDie(t *testing.T) {
	requiredEnvs := []env{
		{name: "OPA_MODULES_DIRECTORY", value: "/modules"},
	}
	defaultAndRequiredEnvironmentVariables := EnvironmentVariables{
		LogLevel:             "info",
		HTTPPort:             "8080",
		UserPropertiesHeader: "miauserproperties",
		UserGroupsHeader:     "miausergroups",
		UserIdHeader:         "miauserid",
		ClientTypeHeader:     "Client-Type",
		DelayShutdownSeconds: 10,
		PathPrefixStandalone: "/eval",
		ServiceVersion:       "latest",

		OPAModulesDirectory:      "/modules",
		AdditionalHeadersToProxy: "miauserid",
		ExposeMetrics:            true,
	}

	t.Run(`returns correctly - with TargetServiceHost`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "TARGET_SERVICE_HOST", value: "http://localhost:3000"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		setEnvs(t, envs)

		actualEnvs := GetEnvOrDie()
		expectedEnvs := defaultAndRequiredEnvironmentVariables
		expectedEnvs.TargetServiceHost = "http://localhost:3000"

		require.Equal(t, expectedEnvs, actualEnvs, "Unexpected envs variables.")
	})

	t.Run(`returns correctly - with Standalone and BindingsCrudServiceURL`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "STANDALONE", value: "true"},
			{name: "BINDINGS_CRUD_SERVICE_URL", value: "http://crud-client"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		setEnvs(t, envs)

		actualEnvs := GetEnvOrDie()
		expectedEnvs := defaultAndRequiredEnvironmentVariables
		expectedEnvs.Standalone = true
		expectedEnvs.BindingsCrudServiceURL = "http://crud-client"

		require.Equal(t, expectedEnvs, actualEnvs, "Unexpected envs variables.")
	})

	t.Run(`returns error - with Standalone and not BindingsCrudServiceURL`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "STANDALONE", value: "true"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		setEnvs(t, envs)

		defer func() {
			r := recover()
			t.Logf("expected panic %+v", r)

		}()

		GetEnvOrDie()
		t.Fail()
	})

	t.Run(`throws - with Standalone to false`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "STANDALONE", value: "false"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		setEnvs(t, envs)

		require.PanicsWithError(t, fmt.Sprintf("missing environment variables, one of %s or %s set to true is required", TargetServiceHostEnvKey, StandaloneEnvKey), func() {
			GetEnvOrDie()
		}, "Unexpected envs variables.")
	})

	t.Run(`throws - no Standalone or TargetServiceHost`, func(t *testing.T) {
		otherEnvs := []env{}
		envs := append(requiredEnvs, otherEnvs...)
		setEnvs(t, envs)

		require.PanicsWithError(t, fmt.Sprintf("missing environment variables, one of %s or %s set to true is required", TargetServiceHostEnvKey, StandaloneEnvKey), func() {
			GetEnvOrDie()
		}, "Unexpected envs variables.")
	})
}

type env struct {
	name  string
	value string
}

func setEnvs(t *testing.T, envsToSet []env) {
	for _, env := range envsToSet {
		t.Setenv(env.name, env.value)
	}
}

func TestGetAdditionalHeadersToProxy(t *testing.T) {
	t.Run("without additional header to proxy use default extra headers", func(t *testing.T) {
		env := EnvironmentVariables{}
		headersToProxy := env.GetAdditionalHeadersToProxy()

		require.Equal(t, extraHeadersKeys, headersToProxy)
	})

	t.Run("with empty additional header to proxy use default extra headers", func(t *testing.T) {
		env := EnvironmentVariables{
			AdditionalHeadersToProxy: "",
		}
		headersToProxy := env.GetAdditionalHeadersToProxy()

		require.Equal(t, extraHeadersKeys, headersToProxy)
	})

	t.Run("with additional header to proxy add default headers to custom headers", func(t *testing.T) {
		env := EnvironmentVariables{
			AdditionalHeadersToProxy: "head1,head2",
		}
		headersToProxy := env.GetAdditionalHeadersToProxy()

		require.Equal(t, []string{"head1", "head2", "x-request-id", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host"}, headersToProxy)
	})

	t.Run("remove duplicated headers in custom and default", func(t *testing.T) {
		env := EnvironmentVariables{
			AdditionalHeadersToProxy: "head1,head2,x-forwarded-for",
		}
		headersToProxy := env.GetAdditionalHeadersToProxy()

		require.Equal(t, []string{"head1", "head2", "x-forwarded-for", "x-request-id", "x-forwarded-proto", "x-forwarded-host"}, headersToProxy)
	})

	t.Run("all extra headers duplicated", func(t *testing.T) {
		env := EnvironmentVariables{
			AdditionalHeadersToProxy: "head1,head2,x-forwarded-for,x-request-id,x-forwarded-proto,x-forwarded-host",
		}
		headersToProxy := env.GetAdditionalHeadersToProxy()

		require.Equal(t, []string{"head1", "head2", "x-forwarded-for", "x-request-id", "x-forwarded-proto", "x-forwarded-host"}, headersToProxy)
	})
}

func TestIsTraceLogLevel(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		env := EnvironmentVariables{
			LogLevel: traceLogLevel,
		}

		require.True(t, env.IsTraceLogLevel())
	})

	t.Run("true", func(t *testing.T) {
		env := EnvironmentVariables{}

		require.False(t, env.IsTraceLogLevel())
	})
}
