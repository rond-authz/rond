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

package custom_builtins

import (
	"encoding/json"
	"net/textproto"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
)

func TestGetHeader(t *testing.T) {

	buildMapTerm := func(t *testing.T, data map[string][]string) *ast.Term {
		t.Helper()

		terms := make([][2]*ast.Term, 0, len(data))

		for key, values := range data {

			valueTermArray := make([]*ast.Term, len(values))
			for i, val := range values {
				valueTermArray[i] = ast.StringTerm(val)
			}

			terms = append(terms, [2]*ast.Term{
				// NOTE: textproto.CanonicalMIMEHeaderKey is used to canonicalize
				// the key in the same way the net/http package does.
				ast.StringTerm(textproto.CanonicalMIMEHeaderKey(key)),
				{Value: ast.NewArray(valueTermArray...)},
			})
		}

		return &ast.Term{Value: ast.NewObject(
			terms...,
		// [2]*ast.Term{
		// 	ast.StringTerm("key"),
		// 	// ast.StringTerm("value"),
		// 	{
		// 		Value: ast.NewArray(
		// 			ast.StringTerm("value"),
		// 		),
		// 	},
		// },
		)}
	}

	t.Run("GetHeader", func(t *testing.T) {
		t.Run("returns correct value when header exists", func(t *testing.T) {
			foundTerm, err := getHeaderDefinition(
				rego.BuiltinContext{},
				ast.StringTerm("X-My-Header"), // search with canonicalized key
				buildMapTerm(t, map[string][]string{"X-My-Header": {"value"}}),
			)
			require.NoError(t, err)
			require.Equal(t, ast.StringTerm("value"), foundTerm)
		})

		t.Run("returns correct value when header exists case-insensitive", func(t *testing.T) {
			foundTerm, err := getHeaderDefinition(
				rego.BuiltinContext{},
				ast.StringTerm("x-my-header"), // search with lower case header key
				buildMapTerm(t, map[string][]string{"X-My-Header": {"value"}}),
			)
			require.NoError(t, err)
			require.Equal(t, ast.StringTerm("value"), foundTerm)
		})

		t.Run("returns error on invalid key", func(t *testing.T) {
			_, err := getHeaderDefinition(
				rego.BuiltinContext{},
				ast.NumberTerm(json.Number("42")),
				buildMapTerm(t, map[string][]string{}),
			)
			require.Error(t, err)
		})

		t.Run("returns error on invalid headers map", func(t *testing.T) {
			_, err := getHeaderDefinition(
				rego.BuiltinContext{},
				ast.StringTerm("x-my-header"),
				ast.BooleanTerm(false),
			)
			require.Error(t, err)
		})
	})
}
