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
		var headers http.Header
		if err := ast.As(a.Value, &headerKey); err != nil {
			return nil, err
		}
		if err := ast.As(b.Value, &headers); err != nil {
			return nil, err
		}
		return ast.StringTerm(headers.Get(headerKey)), nil
	},
)
