package custom_builtins

import (
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/mongoclient"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var MongoFindOneDecl = &ast.Builtin{
	Name: "find_one",
	Decl: types.NewFunction(
		types.Args(
			types.S, // collectionName
			types.A, // query
		),
		types.A, // found document
	),
}

var MongoFindOne = rego.Function2(
	&rego.Function{
		Name: MongoFindOneDecl.Name,
		Decl: MongoFindOneDecl.Decl,
	},
	func(ctx rego.BuiltinContext, collectionNameTerm, queryTerm *ast.Term) (*ast.Term, error) {
		mongoClient, err := mongoclient.GetMongoClientFromContext(ctx.Context)
		if err != nil {
			return nil, err
		}

		var collectionName string
		if err := ast.As(collectionNameTerm.Value, &collectionName); err != nil {
			return nil, err
		}

		query := make(map[string]interface{})
		if err := ast.As(queryTerm.Value, &query); err != nil {
			return nil, err
		}

		result, err := mongoClient.FindOne(ctx.Context, collectionName, query)
		if err != nil {
			return nil, err
		}

		t, err := ast.InterfaceToValue(result)
		if err != nil {
			return nil, err
		}

		return ast.NewTerm(t), nil
	},
)
