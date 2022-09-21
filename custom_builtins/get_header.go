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

package custom_builtins

import (
	"net/http"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

// GetHeader returns the first value corresponding (in case-insensitive mode) to the headerKey
// in the headers of the request, otherwise return an empty string if does not exist.
var GetHeaderDecl = &ast.Builtin{
	Name: "get_header",
	Decl: types.NewFunction(
		types.Args(
			types.S, //headerKey: string
			types.A, //input.request.headers: http.Header (map[string][]string)
		),
		types.S, // First value in the header or "" if does not exist
	),
}

var GetHeaderFunction = rego.Function2(
	&rego.Function{
		Name: GetHeaderDecl.Name,
		Decl: GetHeaderDecl.Decl,
	},
	func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		var headerKey string
		if err := ast.As(a.Value, &headerKey); err != nil {
			return nil, err
		}
		header, err := getHeader(b, headerKey)
		if err != nil {
			return nil, err
		}
		return ast.StringTerm(header), nil
	},
)

func getHeader(astHeaders *ast.Term, headerKey string) (string, error) {
	var headers http.Header
	if err := ast.As(astHeaders.Value, &headers); err != nil {
		return "", err
	}
	return headers.Get(headerKey), nil
}
