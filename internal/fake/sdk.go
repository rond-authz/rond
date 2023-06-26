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

func (s SDKEvaluator) EvaluateRequestPolicy(ctx context.Context, req core.RondInput, userInfo types.User) (core.PolicyResult, error) {
	if s.requestPolicyEvaluatorResult == nil {
		return core.PolicyResult{}, nil
	}
	return core.PolicyResult{}, s.requestPolicyEvaluatorResult.Err
}

func (e SDKEvaluator) EvaluateResponsePolicy(ctx context.Context, rondInput core.RondInput, userInfo types.User, decodedBody any) ([]byte, error) {
	return nil, nil
}

func (s SDKEvaluator) Config() openapi.RondConfig {
	return s.permission
}

func (s SDKEvaluator) PartialResultsEvaluators() core.PartialResultsEvaluators {
	return s.partialEvaluator
}
