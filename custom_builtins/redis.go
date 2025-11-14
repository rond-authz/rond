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
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var RedisGetDecl = &ast.Builtin{
	Name: "redis_get",
	Decl: types.NewFunction(
		types.Args(
			types.S, // key
		),
		types.A, // value
	),
}

var RedisGet = rego.Function1(
	&rego.Function{
		Name: RedisGetDecl.Name,
		Decl: RedisGetDecl.Decl,
	},
	redisGetDef,
)

func redisGetDef(ctx rego.BuiltinContext, keyTerm *ast.Term) (*ast.Term, error) {
	redisClient, err := GetRedisClientFromContext(ctx.Context)
	if err != nil {
		return nil, err
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not set")
	}

	var key string
	if err := ast.As(keyTerm.Value, &key); err != nil {
		return nil, err
	}

	result, err := redisClient.Get(ctx.Context, key)
	if err != nil {
		return nil, err
	}

	t, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}

	return ast.NewTerm(t), nil
}

var RedisSetDecl = &ast.Builtin{
	Name: "redis_set",
	Decl: types.NewFunction(
		types.Args(
			types.S, // key
			types.A, // value
		),
		types.B, // success boolean
	),
}

var RedisSet = rego.Function2(
	&rego.Function{
		Name: RedisSetDecl.Name,
		Decl: RedisSetDecl.Decl,
	},
	redisSetDef,
)

func redisSetDef(ctx rego.BuiltinContext, keyTerm, valueTerm *ast.Term) (*ast.Term, error) {
	redisClient, err := GetRedisClientFromContext(ctx.Context)
	if err != nil {
		return nil, err
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not set")
	}

	var key string
	if err := ast.As(keyTerm.Value, &key); err != nil {
		return nil, err
	}

	var value interface{}
	if err := ast.As(valueTerm.Value, &value); err != nil {
		return nil, err
	}

	// Default expiration: no expiration (0)
	err = redisClient.Set(ctx.Context, key, value, 0)
	if err != nil {
		return nil, err
	}

	return ast.BooleanTerm(true), nil
}

var RedisSetWithExpirationDecl = &ast.Builtin{
	Name: "redis_set_with_expiration",
	Decl: types.NewFunction(
		types.Args(
			types.S, // key
			types.A, // value
			types.N, // expiration in seconds
		),
		types.B, // success boolean
	),
}

var RedisSetWithExpiration = rego.Function3(
	&rego.Function{
		Name: RedisSetWithExpirationDecl.Name,
		Decl: RedisSetWithExpirationDecl.Decl,
	},
	redisSetWithExpirationDef,
)

func redisSetWithExpirationDef(ctx rego.BuiltinContext, keyTerm, valueTerm, expirationTerm *ast.Term) (*ast.Term, error) {
	redisClient, err := GetRedisClientFromContext(ctx.Context)
	if err != nil {
		return nil, err
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not set")
	}

	var key string
	if err := ast.As(keyTerm.Value, &key); err != nil {
		return nil, err
	}

	var value interface{}
	if err := ast.As(valueTerm.Value, &value); err != nil {
		return nil, err
	}

	var expirationSeconds int64
	if err := ast.As(expirationTerm.Value, &expirationSeconds); err != nil {
		return nil, err
	}

	expiration := time.Duration(expirationSeconds) * time.Second
	err = redisClient.Set(ctx.Context, key, value, expiration)
	if err != nil {
		return nil, err
	}

	return ast.BooleanTerm(true), nil
}

var RedisDelDecl = &ast.Builtin{
	Name: "redis_del",
	Decl: types.NewFunction(
		types.Args(
			types.S, // key
		),
		types.B, // success boolean
	),
}

var RedisDel = rego.Function1(
	&rego.Function{
		Name: RedisDelDecl.Name,
		Decl: RedisDelDecl.Decl,
	},
	redisDelDef,
)

func redisDelDef(ctx rego.BuiltinContext, keyTerm *ast.Term) (*ast.Term, error) {
	redisClient, err := GetRedisClientFromContext(ctx.Context)
	if err != nil {
		return nil, err
	}
	if redisClient == nil {
		return nil, fmt.Errorf("redis client not set")
	}

	var key string
	if err := ast.As(keyTerm.Value, &key); err != nil {
		return nil, err
	}

	err = redisClient.Del(ctx.Context, key)
	if err != nil {
		return nil, err
	}

	return ast.BooleanTerm(true), nil
}
