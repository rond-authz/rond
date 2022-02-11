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

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"

	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gotest.tools/v3/assert"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	inputBytes, _ := json.Marshal(input)
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, _ := NewOPAEvaluator(context.Background(), "very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, inputBytes)

		result, err := evaluator.PolicyEvaluator.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.PolicyEvaluator.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
	})
}

func TestCreateRegoInput(t *testing.T) {
	env := config.EnvironmentVariables{}
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

			inputBytes, err := createRegoQueryInput(req, env, user, nil)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})

		t.Run("ignore nil body on method POST", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Content-Type", "application/json")

			inputBytes, err := createRegoQueryInput(req, env, user, nil)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})

		t.Run("added on accepted methods", func(t *testing.T) {
			acceptedMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch}

			for _, method := range acceptedMethods {
				req := httptest.NewRequest(method, "/", bytes.NewReader(reqBodyBytes))
				req.Header.Set("Content-Type", "application/json")
				inputBytes, err := createRegoQueryInput(req, env, user, nil)
				require.Nil(t, err, "Unexpected error")

				require.True(t, strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)), "Unexpected body for method %s", method)
			}
		})

		t.Run("added with content-type specifying charset", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBodyBytes))
			req.Header.Set("Content-Type", "application/json;charset=UTF-8")
			inputBytes, err := createRegoQueryInput(req, env, user, nil)
			require.Nil(t, err, "Unexpected error")

			require.True(t, strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)), "Unexpected body for method %s", http.MethodPost)
		})

		t.Run("reject on method POST but with invalid body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set("Content-Type", "application/json")
			_, err := createRegoQueryInput(req, env, user, nil)
			require.True(t, err != nil)
		})

		t.Run("ignore body on method POST but with another content type", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set("Content-Type", "multipart/form-data")

			inputBytes, err := createRegoQueryInput(req, env, user, nil)
			require.Nil(t, err, "Unexpected error")
			require.True(t, !strings.Contains(string(inputBytes), fmt.Sprintf(`"body":%s`, expectedRequestBody)))
		})
	})
}

func TestCreatePolicyEvaluators(t *testing.T) {
	t.Run("with simplified mock", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		envs := config.EnvironmentVariables{
			APIPermissionsFilePath: "./mocks/simplifiedMock.json",
			OPAModulesDirectory:    "./mocks/rego-policies",
		}
		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, err == nil, "unexpected error")

		opaModuleConfig, err := loadRegoModule(envs.OPAModulesDirectory)
		assert.Assert(t, err == nil, "unexpected error")

		policyEvals, err := setupEvaluators(context.Background(), nil, openApiSpec, opaModuleConfig)
		assert.Assert(t, err == nil, "unexpected error creating evaluators")
		assert.Equal(t, len(policyEvals), 3, "unexpected length")
	})

	t.Run("with complete oas mock", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		ctx := glogger.WithLogger(context.Background(), logrus.NewEntry(log))

		envs := config.EnvironmentVariables{
			APIPermissionsFilePath: "./mocks/pathsConfigAllInclusive.json",
			OPAModulesDirectory:    "./mocks/rego-policies",
		}
		openApiSpec, err := loadOAS(log, envs)
		assert.Assert(t, err == nil, "unexpected error")

		opaModuleConfig, err := loadRegoModule(envs.OPAModulesDirectory)
		assert.Assert(t, err == nil, "unexpected error")

		policyEvals, err := setupEvaluators(ctx, nil, openApiSpec, opaModuleConfig)
		assert.Assert(t, err == nil, "unexpected error creating evaluators")
		assert.Equal(t, len(policyEvals), 4, "unexpected length")
	})
}
