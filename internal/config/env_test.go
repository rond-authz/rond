/*
 * Copyright © 2019-present Mia s.r.l.
 * All rights reserved
 */

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestRequestMiddlewareEnvironments(t *testing.T) {
	t.Run(`RequestMiddlewareEnvironments properly sets env variables into request context`, func(t *testing.T) {
		middleware := RequestMiddlewareEnvironments(EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})

		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			env, ok := r.Context().Value(EnvKey{}).(EnvironmentVariables)
			assert.Assert(t, ok, "Unexpected type in context.")
			assert.Equal(t, env.TargetServiceHost, "localhost:3000", "Unexpected session duration seconds env variable.")
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		builtHandler.ServeHTTP(w, r)

		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})
}

func TestGetEnv(t *testing.T) {
	t.Run(`GetEnv fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetEnv(ctx)
		assert.Assert(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetEnv returns EnvVariables from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), EnvKey{}, EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})
		env, err := GetEnv(ctx)
		assert.Equal(t, err, nil, "Unexpected error.")
		assert.Equal(t, env.TargetServiceHost, "localhost:3000", "Unexpected session duration seconds env variable.")
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

		OPAModulesDirectory:       "/modules",
		ReverseProxyFlushInterval: -1,
	}

	t.Run(`returns correctly - with TargetServiceHost`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "TARGET_SERVICE_HOST", value: "http://localhost:3000"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

		actualEnvs := GetEnvOrDie()
		expectedEnvs := defaultAndRequiredEnvironmentVariables
		expectedEnvs.TargetServiceHost = "http://localhost:3000"

		require.Equal(t, expectedEnvs, actualEnvs, "Unexpected envs variables.")
	})

	t.Run(`returns correctly - with FLUSH INTERVAL`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "TARGET_SERVICE_HOST", value: "abc"},
			{name: "REVERSE_PROXY_FLUSH_INTERVAL", value: "25"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

		actualEnvs := GetEnvOrDie()

		require.Equal(t, 25, actualEnvs.ReverseProxyFlushInterval, "Unexpected session duration seconds env variable.")
	})

	t.Run(`returns correctly - with FLUSH INTERVAL 0`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "TARGET_SERVICE_HOST", value: "abc"},
			{name: "REVERSE_PROXY_FLUSH_INTERVAL", value: "0"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

		actualEnvs := GetEnvOrDie()

		require.Equal(t, 0, actualEnvs.ReverseProxyFlushInterval, "Unexpected session duration seconds env variable.")
	})

	t.Run(`returns correctly - with Standalone and BindingsCrudServiceURL`, func(t *testing.T) {
		otherEnvs := []env{
			{name: "STANDALONE", value: "true"},
			{name: "BINDINGS_CRUD_SERVICE_URL", value: "http://crud-client"},
		}
		envs := append(requiredEnvs, otherEnvs...)
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

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
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

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
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

		require.PanicsWithError(t, fmt.Sprintf("missing environment variables, one of %s or %s set to true is required", TargetServiceHostEnvKey, StandaloneEnvKey), func() {
			GetEnvOrDie()
		}, "Unexpected envs variables.")
	})

	t.Run(`throws - no Standalone or TargetServiceHost`, func(t *testing.T) {
		otherEnvs := []env{}
		envs := append(requiredEnvs, otherEnvs...)
		unsetEnvs := setEnvs(envs)
		defer unsetEnvs()

		require.PanicsWithError(t, fmt.Sprintf("missing environment variables, one of %s or %s set to true is required", TargetServiceHostEnvKey, StandaloneEnvKey), func() {
			GetEnvOrDie()
		}, "Unexpected envs variables.")
	})
}

type env struct {
	name  string
	value string
}

func setEnvs(envsToSet []env) func() {
	for _, env := range envsToSet {
		os.Setenv(env.name, env.value)
	}

	return func() {
		for _, env := range envsToSet {
			os.Unsetenv(env.name)
		}
	}
}
