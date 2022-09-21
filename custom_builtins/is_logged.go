package custom_builtins

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var IsLoggedDecl = &ast.Builtin{
	Name: "is_logged",
	Decl: types.NewFunction(
		types.Args(
			types.A, //input.request.headers: http.Header (map[string][]string)
		),
		types.B, // boolean
	),
}

var IsLoggedFunction = rego.Function1(
	&rego.Function{
		Name: IsLoggedDecl.Name,
		Decl: IsLoggedDecl.Decl,
	},
	func(context rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
		authorization, err := getHeader(a, "authorization")
		if err != nil {
			return nil, err
		}

		// c :=context.Context

		logged := false
		if authorization != "" {
			_, err := parse_jwe(context.Context, authorization)
			logged = err == nil
		}

		return ast.BooleanTerm(logged), nil
	},
)
