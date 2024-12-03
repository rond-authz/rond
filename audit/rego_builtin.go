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

package audit

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var SetLabelsDecl = &ast.Builtin{
	Name: "set_audit_labels",
	Decl: types.NewFunction(
		types.Args(
			types.A, // payload
		),
		types.A,
	),
}

var SetLabels = rego.Function1(
	&rego.Function{
		Name: SetLabelsDecl.Name,
		Decl: SetLabelsDecl.Decl,
	},
	func(bctx rego.BuiltinContext, dataToStore *ast.Term) (*ast.Term, error) {
		auditCache, err := GetAuditCache(bctx.Context)
		if err != nil {
			return nil, fmt.Errorf("missing audit cache in context")
		}

		data := make(map[string]interface{})
		if err := ast.As(dataToStore.Value, &data); err != nil {
			return nil, err
		}

		auditCache.Store(data)
		return ast.BooleanTerm(true), nil
	},
)
