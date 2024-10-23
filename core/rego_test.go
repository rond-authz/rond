// Copyright 2024 Mia srl
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
	"context"
	"net/http"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
)

func TestNewOPAEvaluator(t *testing.T) {
	t.Run("policy sanitization", func(t *testing.T) {
		opaModule := MustNewOPAModuleConfig("", "package policies very_composed_policy {true}")
		evaluator, err := newRegoInstanceBuilder("very.composed.policy", opaModule, nil)
		require.NoError(t, err)

		result, err := evaluator.Eval(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.True(t, result.Allowed(), "Unexpected failing policy")

		parialResult, err := evaluator.Partial(context.TODO())
		require.Nil(t, err, "unexpected error")
		require.Equal(t, 1, len(parialResult.Queries), "Unexpected failing policy")
	})
}

func TestGetHeaderFunction(t *testing.T) {
	headerKeyMocked := "exampleKey"
	headerValueMocked := "value"

	opaModule := MustNewOPAModuleConfig("", `package policies
		todo { get_header("ExAmPlEkEy", input.headers) == "value" }`)
	queryString := "todo"

	t.Run("if header key exists", func(t *testing.T) {
		headers := http.Header{}
		headers.Add(headerKeyMocked, headerValueMocked)
		input := map[string]interface{}{
			"headers": headers,
		}

		opaEvaluator, err := newRegoInstanceBuilder(queryString, opaModule, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		preparedEval, err := opaEvaluator.PrepareForEval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		preparedPartial, err := opaEvaluator.PrepareForPartial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		results, err := preparedEval.Eval(context.TODO(), rego.EvalInput(input))
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, results.Allowed(), "The input is not allowed by rego")

		partialResults, err := preparedPartial.Partial(context.TODO(), rego.EvalInput(input))
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 1, "Rego policy allows illegal input")
	})

	t.Run("if header key not exists", func(t *testing.T) {
		input := map[string]interface{}{
			"headers": http.Header{},
		}

		opaEvaluator, err := newRegoInstanceBuilder(queryString, opaModule, nil)
		require.NoError(t, err, "Unexpected error during creation of opaEvaluator")

		preparedEval, err := opaEvaluator.PrepareForEval(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")
		preparedPartial, err := opaEvaluator.PrepareForPartial(context.TODO())
		require.NoError(t, err, "Unexpected error during rego validation")

		results, err := preparedEval.Eval(context.TODO(), rego.EvalInput(input))
		require.NoError(t, err, "Unexpected error during rego validation")
		require.True(t, !results.Allowed(), "Rego policy allows illegal input")

		partialResults, err := preparedPartial.Partial(context.TODO(), rego.EvalInput(input))
		require.NoError(t, err, "Unexpected error during rego validation")

		require.Len(t, partialResults.Queries, 0, "Rego policy allows illegal input")
	})
}
