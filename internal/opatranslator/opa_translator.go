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

package opatranslator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/samber/lo"
	"go.mongodb.org/mongo-driver/bson"
)

func extractQueryPipeline(query Queries, _ int) bson.M {
	return query.Pipeline
}

var ErrEmptyQuery = errors.New("empty query")

const minimumResultLength = 3

type OPAClient struct{}

func (c *OPAClient) ProcessQuery(pq *rego.PartialQueries) (bson.M, error) {
	var queries []Queries
	for i := range pq.Queries {
		pipeline := &[]bson.M{}
		for _, expr := range pq.Queries[i] {
			if !expr.IsCall() {
				continue
			}

			if len(expr.Operands()) != 2 {
				return nil, fmt.Errorf("invalid expression: too many arguments")
			}

			var value interface{}
			var processedTerm []string
			var err error
			for _, term := range expr.Operands() {
				if ast.IsConstant(term.Value) {
					value, err = ast.JSON(term.Value)
					if err != nil {
						return nil, fmt.Errorf("error converting term to JSON: %v", err)
					}
				} else {
					processedTerm = processTerm(term.String())
				}
			}

			if processedTerm == nil {
				return nil, nil
			}
			stringifiedOperator := expr.Operator().String()
			operationHandled := HandleOperations(stringifiedOperator, pipeline, processedTerm[1], value)
			if !operationHandled {
				return nil, fmt.Errorf("invalid expression: operator not supported: %v", expr.Operator().String())
			}
		}
		k1 := Queries{Pipeline: bson.M{"$and": *pipeline}}
		queries = append(queries, k1)
	}

	if len(queries) == 0 {
		return nil, fmt.Errorf("%w: RBAC policy evaluation and query generation failed", ErrEmptyQuery)
	}

	mongoQueries := lo.Map(queries, extractQueryPipeline)

	finalQuery := bson.M{"$or": mongoQueries}

	return finalQuery, nil
}

func processTerm(query string) []string {
	splitQ := strings.Split(query, ".")
	result := lo.Map(splitQ, removeOpenBrace)

	if result == nil {
		return nil
	}
	if queryIsEmpty := len(result) < minimumResultLength; queryIsEmpty {
		return nil
	}

	indexName := result[1]
	fieldName := result[2]
	if len(result) > 2 {
		fieldName = strings.Join(result[2:], ".")
	}

	return []string{indexName, fieldName}
}

func removeOpenBrace(input string, _ int) string {
	return strings.Split(input, "[")[0]
}
