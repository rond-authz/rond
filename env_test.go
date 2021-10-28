/*
 * Copyright © 2019-present Mia s.r.l.
 * All rights reserved
 */

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
)

func TestRequestMiddlewareEnvironments(t *testing.T) {
	t.Run(`RequestMiddlewareEnvironments properly sets env variables into request context`, func(t *testing.T) {
		middleware := RequestMiddlewareEnvironments(EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})

		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			env, ok := r.Context().Value(envKey{}).(EnvironmentVariables)
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
		ctx := context.WithValue(context.Background(), envKey{}, EnvironmentVariables{
			TargetServiceHost: "localhost:3000",
		})
		env, err := GetEnv(ctx)
		assert.Equal(t, err, nil, "Unexpected error.")
		assert.Equal(t, env.TargetServiceHost, "localhost:3000", "Unexpected session duration seconds env variable.")
	})
}
