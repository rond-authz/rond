package opatranslator

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"go.mongodb.org/mongo-driver/bson"
)

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
			if isEqualityOperator(expr.Operator().String()) {
				HandleEquals(pipeline, processedTerm[1], value)
			} else if isRangeOperator(expr.Operator().String()) {
				if expr.Operator().String() == "lt" {
					HandleLessThan(pipeline, processedTerm[1], value)
				} else if expr.Operator().String() == "gt" {
					HandleGreaterThan(pipeline, processedTerm[1], value)
				} else if expr.Operator().String() == "lte" {
					HandleLessThanEquals(pipeline, processedTerm[1], value)
				} else if expr.Operator().String() == "gte" {
					HandleGreaterThanEquals(pipeline, processedTerm[1], value)
				}
			} else if expr.Operator().String() == "neq" {
				HandleNotEquals(pipeline, processedTerm[1], value)
			} else {
				return nil, fmt.Errorf("invalid expression: operator not supported: %v", expr.Operator().String())
			}
		}
		k1 := Queries{Pipeline: bson.M{"$and": *pipeline}}
		queries = append(queries, k1)
	}
	if len(queries) == 0 {
		return nil, fmt.Errorf("RBAC policy evaluation and query generation failed")
	}
	var mongoQueries []bson.M
	for _, q := range queries {
		mongoQueries = append(mongoQueries, q.Pipeline)
	}

	finalQuery := bson.M{"$or": mongoQueries}

	return finalQuery, nil
}

func processTerm(query string) []string {
	splitQ := strings.Split(query, ".")
	var result []string
	for _, term := range splitQ {
		result = append(result, removeOpenBrace(term))
	}
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

func removeOpenBrace(input string) string {
	return strings.Split(input, "[")[0]
}

func isEqualityOperator(op string) bool {
	return op == "eq" || op == "equal"
}

func isRangeOperator(op string) bool {
	return op == "lt" || op == "gt" || op == "lte" || op == "gte"
}