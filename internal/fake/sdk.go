// Copyright 2023 Mia srl
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

package fake

import (
	"context"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/sdk"
)

type RequestPolicyEvaluatorResult struct {
	Err error
}

type SDKEvaluator struct {
	partialEvaluator core.PartialResultsEvaluators
	permission       core.RondConfig

	requestPolicyEvaluatorResult *RequestPolicyEvaluatorResult
}

func NewSDKEvaluator(
	partialEvaluator core.PartialResultsEvaluators,
	permission core.RondConfig,
	requestPolicyEvaluatorResult *RequestPolicyEvaluatorResult,
) sdk.Evaluator {
	return SDKEvaluator{
		partialEvaluator: partialEvaluator,
		permission:       permission,

		requestPolicyEvaluatorResult: requestPolicyEvaluatorResult,
	}
}

func (s SDKEvaluator) EvaluateRequestPolicy(ctx context.Context, input core.Input) (sdk.PolicyResult, error) {
	if s.requestPolicyEvaluatorResult == nil {
		return sdk.PolicyResult{}, nil
	}
	return sdk.PolicyResult{}, s.requestPolicyEvaluatorResult.Err
}

func (e SDKEvaluator) EvaluateResponsePolicy(ctx context.Context, input core.Input) ([]byte, error) {
	return nil, nil
}

func (s SDKEvaluator) Config() core.RondConfig {
	return s.permission
}
