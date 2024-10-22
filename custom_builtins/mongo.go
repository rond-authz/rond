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
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
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
		mongoClient, err := GetMongoClientFromContext(ctx.Context)
		if err != nil {
			return nil, err
		}
		if mongoClient == nil {
			return nil, fmt.Errorf("mongo client not set")
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

var MongoFindManyDecl = &ast.Builtin{
	Name: "find_many",
	Decl: types.NewFunction(
		types.Args(
			types.S, // collectionName
			types.A, // query
		),
		types.A, // found document
	),
}

var MongoFindMany = rego.Function2(
	&rego.Function{
		Name: MongoFindManyDecl.Name,
		Decl: MongoFindManyDecl.Decl,
	},
	func(ctx rego.BuiltinContext, collectionNameTerm, queryTerm *ast.Term) (*ast.Term, error) {
		mongoClient, err := GetMongoClientFromContext(ctx.Context)
		if err != nil {
			return nil, err
		}
		if mongoClient == nil {
			return nil, fmt.Errorf("mongo client not set")
		}

		var collectionName string
		if err := ast.As(collectionNameTerm.Value, &collectionName); err != nil {
			return nil, err
		}

		query := make(map[string]interface{})
		if err := ast.As(queryTerm.Value, &query); err != nil {
			return nil, err
		}

		result, err := mongoClient.FindMany(ctx.Context, collectionName, query)
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

func MongoFindOneAst(ctx topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	mongoClient, err := GetMongoClientFromContext(ctx.Context)
	if err != nil {
		return err
	}
	if mongoClient == nil {
		return fmt.Errorf("mongo client not set")
	}

	collectionNameTerm := operands[0]
	queryTerm := operands[1]

	var collectionName string
	if err := ast.As(collectionNameTerm.Value, &collectionName); err != nil {
		return err
	}

	query := make(map[string]interface{})
	if err := ast.As(queryTerm.Value, &query); err != nil {
		return err
	}

	result, err := mongoClient.FindOne(ctx.Context, collectionName, query)
	if err != nil {
		return err
	}

	t, err := ast.InterfaceToValue(result)
	if err != nil {
		return err
	}

	return iter(ast.NewTerm(t))
}

func MongoFindManyAst(ctx topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
	mongoClient, err := GetMongoClientFromContext(ctx.Context)
	if err != nil {
		return err
	}
	if mongoClient == nil {
		return fmt.Errorf("mongo client not set")
	}
	collectionNameTerm := operands[0]
	queryTerm := operands[1]

	var collectionName string
	if err := ast.As(collectionNameTerm.Value, &collectionName); err != nil {
		return err
	}

	query := make(map[string]interface{})
	if err := ast.As(queryTerm.Value, &query); err != nil {
		return err
	}

	result, err := mongoClient.FindMany(ctx.Context, collectionName, query)
	if err != nil {
		return err
	}

	t, err := ast.InterfaceToValue(result)
	if err != nil {
		return err
	}

	return iter(ast.NewTerm(t))
}
