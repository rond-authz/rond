// Copyright 2025 Mia srl
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

package audit

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
)

func prepareContext(t *testing.T, agent Agent) rego.BuiltinContext {
	t.Helper()
	ctx := context.Background()

	if agent != nil {
		ctx = WithAuditCache(ctx, agent)
	}

	return rego.BuiltinContext{
		Context: ctx,
	}
}

func TestSetLabelsBuiltinDefinition(t *testing.T) {
	t.Run("returns error if no cache in context", func(t *testing.T) {
		ctx := prepareContext(t, nil)
		_, err := setLabelsBuiltinDefinition(ctx, &ast.Term{})
		require.EqualError(t, err, "missing audit cache in context")
	})

	t.Run("returns error if data is not a map", func(t *testing.T) {
		ctx := prepareContext(t, &testAgent{
			MockCache: &SingleRecordCache{
				data: make(Data),
			},
		})
		_, err := setLabelsBuiltinDefinition(ctx, &ast.Term{
			Value: ast.Boolean(false),
		})
		require.EqualError(t, err, "json: cannot unmarshal bool into Go value of type map[string]interface {}")
	})

	t.Run("Stores data in cache", func(t *testing.T) {
		cache := &SingleRecordCache{
			data: make(Data),
		}
		ctx := prepareContext(t, &testAgent{
			MockCache: cache,
		})
		result, err := setLabelsBuiltinDefinition(ctx, &ast.Term{
			Value: ast.NewObject(
				[2]*ast.Term{
					ast.StringTerm("key"),
					ast.StringTerm("value"),
				},
			),
		})
		require.NoError(t, err)
		require.Equal(t, ast.BooleanTerm(true), result)

		require.Equal(t, "value", cache.data["key"])
	})
}
