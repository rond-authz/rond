package fake

import (
	"net/http"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"
)

type RequestPolicyEvaluatorResult struct {
	Err error
}

type SDKEvaluator struct {
	partialEvaluator core.PartialResultsEvaluators
	permission       openapi.RondConfig

	requestPolicyEvaluatorResult *RequestPolicyEvaluatorResult
}

func NewSDKEvaluator(
	partialEvaluator core.PartialResultsEvaluators,
	permission openapi.RondConfig,
	requestPolicyEvaluatorResult *RequestPolicyEvaluatorResult,
) core.SDKEvaluator {
	return SDKEvaluator{
		partialEvaluator: partialEvaluator,
		permission:       permission,

		requestPolicyEvaluatorResult: requestPolicyEvaluatorResult,
	}
}

func (s SDKEvaluator) EvaluateRequestPolicy(req *http.Request, userInfo types.User, permission *openapi.RondConfig) (core.PolicyResult, error) {
	if s.requestPolicyEvaluatorResult == nil {
		return core.PolicyResult{}, nil
	}
	return core.PolicyResult{}, s.requestPolicyEvaluatorResult.Err
}

func (s SDKEvaluator) Permission() openapi.RondConfig {
	return s.permission
}

func (s SDKEvaluator) PartialResultsEvaluators() core.PartialResultsEvaluators {
	return s.partialEvaluator
}
