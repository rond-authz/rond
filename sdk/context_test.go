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
	"testing"

	"github.com/rond-authz/rond/openapi"
	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		rondConfig := openapi.RondConfig{
			RequestFlow: openapi.RequestFlow{
				PolicyName:    "todo",
				GenerateQuery: true,
			},
			ResponseFlow: openapi.ResponseFlow{
				PolicyName: "other",
			},
		}

		expectedEvaluator := evaluator{
			rondConfig: rondConfig,
		}

		ctx = WithEvaluatorSDK(ctx, expectedEvaluator)

		actualEvaluator, err := GetEvaluatorSKD(ctx)
		require.NoError(t, err)
		require.Equal(t, expectedEvaluator, actualEvaluator)
	})

	t.Run("throws if not in context", func(t *testing.T) {
		actualEvaluator, err := GetEvaluatorSKD(context.Background())
		require.EqualError(t, err, "no SDKEvaluator found in request context")
		require.Nil(t, actualEvaluator)
	})
}
