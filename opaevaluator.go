package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

type Evaluator interface {
	Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error)
}

// TODO: This should be transformed to a map having as keys the API VERB+PATH
// and as content a struct with permssions and the actual opa query eval
type OPAEvaluator struct {
	PermissionQuery         Evaluator
	RequiredAllowPermission string
}

func NewOPAEvaluator(policy string, opaModuleConfig *OPAModuleConfig) (*OPAEvaluator, error) {
	sanitizedPolicy := strings.Replace(policy, ".", "_", -1)
	queryString := fmt.Sprintf("data.policies.%s", sanitizedPolicy)
	query, err := rego.New(
		rego.Query(queryString),
		rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
		getHeaderFunction,
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, err
	}

	return &OPAEvaluator{
		PermissionQuery:         query,
		RequiredAllowPermission: policy,
	}, nil
}

type TruthyEvaluator struct{}

func (e *TruthyEvaluator) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return rego.ResultSet{
		rego.Result{
			Expressions: []*rego.ExpressionValue{
				{Value: true},
			},
		},
	}, nil
}
