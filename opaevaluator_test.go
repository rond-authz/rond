package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, err := NewOPAEvaluator("very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, input)
		require.Nil(t, err, "unexpected error")
		require.Equal(t, "very.composed.policy", evaluator.RequiredAllowPermission)

		result, err := evaluator.PermissionQuery.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.PermissionQuery.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
	})
}
