package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

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
