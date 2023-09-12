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

package core

import "fmt"

var (
	ErrMissingRegoModules   = fmt.Errorf("no rego module found in directory")
	ErrRegoModuleReadFailed = fmt.Errorf("failed rego file read")
	ErrInvalidConfig        = fmt.Errorf("invalid rond configuration")

	ErrEvaluatorCreationFailed = fmt.Errorf("error during evaluator creation")
	ErrEvaluatorNotFound       = fmt.Errorf("evaluator not found")

	ErrPolicyEvalFailed         = fmt.Errorf("policy evaluation failed")
	ErrPartialPolicyEvalFailed  = fmt.Errorf("partial %w", ErrPolicyEvalFailed)
	ErrResponsePolicyEvalFailed = fmt.Errorf("response %w", ErrPolicyEvalFailed)
	ErrPolicyNotAllowed         = fmt.Errorf("policy not allowed")

	ErrFailedInputParse                  = fmt.Errorf("failed input parse")
	ErrFailedInputEncode                 = fmt.Errorf("failed input encode")
	ErrFailedInputRequestParse           = fmt.Errorf("failed request body parse")
	ErrFailedInputRequestDeserialization = fmt.Errorf("failed request body deserialization")
	ErrRondConfigNotExists               = fmt.Errorf("rond config does not exist")
)
