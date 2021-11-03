package mocks

import (
	"context"

	"github.com/open-policy-agent/opa/rego"
)

type MockEvaluator struct {
	ResultSet   rego.ResultSet
	ResultError error
}

func (m *MockEvaluator) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	if m.ResultError != nil {
		return nil, m.ResultError
	}
	return m.ResultSet, nil
}
