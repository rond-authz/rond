package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestOPAMiddleware(t *testing.T) {
	t.Run(`RequestMiddlewareEnvironments properly sets env variables into request context`, func(t *testing.T) {
		var openAPISpec *OpenAPISpec

		opaModule := &OPAModuleConfig{
			Name: "example.rego",
			Content: `package example
todo { true }`,
		}
		middleware := OPAMiddleware(opaModule, openAPISpec)

		builtHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opaModuleConfigFromContext, ok := r.Context().Value(OPAEvaluatorKey{}).(*OPAEvaluator)
			require.True(t, ok, "Unexpected type in context.")
			require.True(t, opaModuleConfigFromContext != nil, "Unexpected opa module evaluator in context, nil found.")
			w.WriteHeader(http.StatusOK)
		}))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		builtHandler.ServeHTTP(w, r)

		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})
}

func TestGetOPAEvaluator(t *testing.T) {
	t.Run(`GetOPAEvaluator fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetOPAEvaluator(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetOPAEvaluator returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), OPAEvaluatorKey{}, &OPAEvaluator{})
		opaEval, err := GetOPAEvaluator(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, opaEval != nil, "localhost:3000", "Unexpected session duration seconds env variable.")
	})
}
