package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"

	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	inputBytes, _ := json.Marshal(input)
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, err := NewOPAEvaluator("very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, inputBytes)
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

func TestCreateRegoInput(t *testing.T) {
	env := EnvironmentVariables{}
	user := types.User{}

	t.Run("body integration", func(t *testing.T) {
		expectedRequestBody := []byte(`{"Key":42}`)
		reqBody := struct{ Key int }{
			Key: 42,
		}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.Nil(t, err, "Unexpected error")

		t.Run("ignored on method GET", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(reqBodyBytes))

			inputBytes, err := createRegoQueryInput(req, env, user)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})

		t.Run("ignore nil body on method POST", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Content-Type", "application/json")

			inputBytes, err := createRegoQueryInput(req, env, user)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})

		t.Run("added on method accepted methods", func(t *testing.T) {
			acceptedMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch}

			for _, method := range acceptedMethods {
				req := httptest.NewRequest(method, "/", bytes.NewReader(reqBodyBytes))
				req.Header.Set("Content-Type", "application/json")
				inputBytes, err := createRegoQueryInput(req, env, user)
				require.Nil(t, err, "Unexpected error")

				require.True(t, strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)), "Unexpected body for method %s", method)
			}
		})

		t.Run("reject on method POST but with invalid body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set("Content-Type", "application/json")
			_, err := createRegoQueryInput(req, env, user)
			require.True(t, err != nil)
		})

		t.Run("ignore body on method POST but with another content type", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set("Content-Type", "multipart/form-data")

			inputBytes, err := createRegoQueryInput(req, env, user)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})
	})
}
