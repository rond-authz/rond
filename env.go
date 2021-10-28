/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mia-platform/configlib"
)

// EnvironmentVariables struct with the mapping of desired
// environment variables.
type EnvironmentVariables struct {
	LogLevel               string
	HTTPPort               string
	OriginalProtocolHeader string
	ServicePrefix          string
	ServiceVersion         string
	HostURL                string

	DelayShutdownSeconds int
}

var envVariablesConfig = []configlib.EnvConfig{
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
		Key:          "SERVICE_PREFIX",
		Variable:     "ServicePrefix",
		DefaultValue: "",
	},
	{
		Key:      "SESSION_SCOPE",
		Variable: "SessionScope",
	},
	{
		Key:      "ORIGINAL_PROTOCOL_HEADER",
		Variable: "OriginalProtocolHeader",
	},
	{
		Key:      "SERVICE_VERSION",
		Variable: "ServiceVersion",
	},
	{
		Key:      "HOST_URL",
		Variable: "HostURL",
	},
	{
		Key:          "DELAY_SHUTDOWN_SECONDS",
		Variable:     "DelayShutdownSeconds",
		DefaultValue: "10",
	},
}

type envKey struct{}

// RequestMiddlewareEnvironments is a gorilla/mux middleware used to inject
// env variables into requests.
func RequestMiddlewareEnvironments(env EnvironmentVariables) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), envKey{}, env)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetEnv can be used by a request handler to get environment variables from its context.
func GetEnv(requestContext context.Context) (EnvironmentVariables, error) {
	env, ok := requestContext.Value(envKey{}).(EnvironmentVariables)
	if !ok {
		return EnvironmentVariables{}, fmt.Errorf("no environment in request context")
	}

	return env, nil
}
