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

package sdk

import (
	"context"
	"errors"
)

var (
	ErrGetEvaluator = errors.New("no Evaluator found in request context")
)

type sdkKey struct{}

func WithEvaluator(ctx context.Context, evaluator Evaluator) context.Context {
	return context.WithValue(ctx, sdkKey{}, evaluator)
}

func GetEvaluator(ctx context.Context) (Evaluator, error) {
	sdk, ok := ctx.Value(sdkKey{}).(Evaluator)
	if !ok {
		return nil, ErrGetEvaluator
	}

	return sdk, nil
}
