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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	input := map[string]interface{}{}
	inputBytes, _ := json.Marshal(input)
	t.Run("policy sanitization", func(t *testing.T) {
		evaluator, _ := NewOPAEvaluator(context.Background(), "very.composed.policy", &OPAModuleConfig{Content: "package policies very_composed_policy {true}"}, inputBytes, nil)

		result, err := evaluator.PolicyEvaluator.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.PolicyEvaluator.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
	})
}

func TestCreatePolicyEvaluators(t *testing.T) {
	t.Run("with simplified mock", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		logger := logrus.NewEntry(log)
		ctx := context.Background()

		opaModuleDirectory := "../mocks/rego-policies"
		loadOptions := openapi.LoadOptions{
			APIPermissionsFilePath: "../mocks/simplifiedMock.json",
		}
		openApiSpec, err := openapi.LoadOASFromFileOrNetwork(log, loadOptions)
		require.NoError(t, err, "unexpected error")

		opaModuleConfig, err := LoadRegoModule(opaModuleDirectory)
		require.NoError(t, err, "unexpected error")

		policyEvals, err := SetupEvaluators(ctx, logger, nil, openApiSpec, opaModuleConfig, nil)
		require.NoError(t, err, "unexpected error creating evaluators")
		require.Len(t, policyEvals, 4, "unexpected length")
	})

	t.Run("with complete oas mock", func(t *testing.T) {
		log, _ := test.NewNullLogger()
		logger := logrus.NewEntry(log)
		ctx := context.Background()

		opaModulesDirectory := "../mocks/rego-policies"

		loadOptions := openapi.LoadOptions{
			APIPermissionsFilePath: "../mocks/pathsConfigAllInclusive.json",
		}
		openApiSpec, err := openapi.LoadOASFromFileOrNetwork(log, loadOptions)
		require.NoError(t, err, "unexpected error")

		opaModuleConfig, err := LoadRegoModule(opaModulesDirectory)
		require.NoError(t, err, "unexpected error")

		policyEvals, err := SetupEvaluators(ctx, logger, nil, openApiSpec, opaModuleConfig, nil)
		require.NoError(t, err, "unexpected error creating evaluators")
		require.Len(t, policyEvals, 4, "unexpected length")
	})
}

func TestBuildRolesMap(t *testing.T) {
	roles := []types.Role{
		{
			RoleID:      "role1",
			Permissions: []string{"permission1", "permission2"},
		},
		{
			RoleID:      "role2",
			Permissions: []string{"permission3", "permission4"},
		},
	}
	result := buildRolesMap(roles)
	expected := map[string][]string{
		"role1": {"permission1", "permission2"},
		"role2": {"permission3", "permission4"},
	}
	require.Equal(t, expected, result)
}

func TestCreateQueryEvaluator(t *testing.T) {
	policy := `package policies
allow {
	true
}
column_policy{
	false
}
`
	permission := openapi.XPermission{
		AllowPermission: "allow",
		ResponseFilter: openapi.ResponseFilterConfiguration{
			Policy: "column_policy",
		},
	}

	opaModuleConfig := &OPAModuleConfig{Name: "mypolicy.rego", Content: policy}
	ctx := createContext(t,
		context.Background(),
		config.EnvironmentVariables{TargetServiceHost: "test"},
		nil,
		&openapi.RondConfig{
			RequestFlow:  openapi.RequestFlow{PolicyName: "allow"},
			ResponseFlow: openapi.ResponseFlow{PolicyName: "column_policy"},
		},
		opaModuleConfig,
		nil,
	)

	r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
	require.NoError(t, err, "Unexpected error")
	log, _ := test.NewNullLogger()
	logger := logrus.NewEntry(log)

	input := Input{Request: InputRequest{}, Response: InputResponse{}}
	inputBytes, _ := json.Marshal(input)

	t.Run("create evaluator with allowPolicy", func(t *testing.T) {
		evaluator, err := opaModuleConfig.CreateQueryEvaluator(context.Background(), logger, r, permission.AllowPermission, inputBytes, nil, nil)
		require.True(t, evaluator != nil)
		require.NoError(t, err, "Unexpected status code.")
	})

	t.Run("create  evaluator with policy for column filtering", func(t *testing.T) {
		evaluator, err := opaModuleConfig.CreateQueryEvaluator(context.Background(), logger, r, permission.ResponseFilter.Policy, inputBytes, nil, nil)
		require.True(t, evaluator != nil)
		require.NoError(t, err, "Unexpected status code.")
	})
}

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrintHook(&buf, "policy-name")

	err := h.Print(print.Context{}, "the print message")
	require.NoError(t, err)

	var re = regexp.MustCompile(`"time":\d+`)
	require.JSONEq(t, `{"level":10,"msg":"the print message","time":123,"policyName":"policy-name"}`, string(re.ReplaceAll(buf.Bytes(), []byte("\"time\":123"))))
}

func createContext(
	t *testing.T,
	originalCtx context.Context,
	env config.EnvironmentVariables,
	mongoClient *mocks.MongoClientMock,
	permission *openapi.RondConfig,
	opaModuleConfig *OPAModuleConfig,
	partialResultEvaluators PartialResultsEvaluators,
) context.Context {
	t.Helper()

	var partialContext context.Context
	partialContext = context.WithValue(originalCtx, config.EnvKey{}, env)
	partialContext = context.WithValue(partialContext, openapi.XPermissionKey{}, permission)
	partialContext = context.WithValue(partialContext, OPAModuleConfigKey{}, opaModuleConfig)
	if mongoClient != nil {
		partialContext = context.WithValue(partialContext, types.MongoClientContextKey{}, mongoClient)
	}
	partialContext = context.WithValue(partialContext, PartialResultsEvaluatorConfigKey{}, partialResultEvaluators)

	log, _ := test.NewNullLogger()
	partialContext = glogger.WithLogger(partialContext, logrus.NewEntry(log))

	partialContext = context.WithValue(partialContext, openapi.RouterInfoKey{}, openapi.RouterInfo{
		MatchedPath:   "/matched/path",
		RequestedPath: "/requested/path",
		Method:        "GET",
	})

	partialContext = metrics.WithValue(partialContext, metrics.SetupMetrics("test_rond"))

	return partialContext
}
func TestGetHeaderFunction(t *testing.T) {
	headerKeyMocked := "exampleKey"
	headerValueMocked := "value"

	opaModule := &OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		todo { get_header("ExAmPlEkEy", input.headers) == "value" }`,
	}
	queryString := "todo"

	t.Run("if header key exists", func(t *testing.T) {
		headers := http.Header{}
		headers.Add(headerKeyMocked, headerValueMocked)
		input := map[string]interface{}{
			"headers": headers,
		}
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, results.Allowed(), "The input is not allowed by rego")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 1, "Rego policy allows illegal input")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}
		inputBytes, _ := json.Marshal(input)

		opaEvaluator, err := NewOPAEvaluator(context.Background(), queryString, opaModule, inputBytes, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		results, err := opaEvaluator.PolicyEvaluator.Eval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := opaEvaluator.PolicyEvaluator.Partial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 0, "Rego policy allows illegal input")
	})
}

func TestGetOPAModuleConfig(t *testing.T) {
	t.Run(`GetOPAModuleConfig fails because no key has been passed`, func(t *testing.T) {
		ctx := context.Background()
		env, err := GetOPAModuleConfig(ctx)
		require.True(t, err != nil, "An error was expected.")
		t.Logf("Expected error: %s - env: %+v", err.Error(), env)
	})

	t.Run(`GetOPAModuleConfig returns OPAEvaluator from context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), OPAModuleConfigKey{}, &OPAModuleConfig{})
		opaEval, err := GetOPAModuleConfig(ctx)
		require.True(t, err == nil, "Unexpected error.")
		require.True(t, opaEval != nil, "OPA Module config not found.")
	})
}
