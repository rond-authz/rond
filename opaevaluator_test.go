package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, err := NewOPAEvaluator("very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"})
		require.Nil(t, err, "unexpected error")
		require.Equal(t, "very.composed.policy", evaluator.RequiredAllowPermission)

		result, err := evaluator.PermissionQuery.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")
	})
}
