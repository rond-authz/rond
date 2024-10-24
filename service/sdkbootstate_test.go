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

package service

import (
	"testing"
	"time"

	"github.com/rond-authz/rond/internal/fake"
	"github.com/stretchr/testify/require"
)

func TestSDKBootState(t *testing.T) {
	t.Run("flow with routine", func(t *testing.T) {
		sdkBootState := NewSDKBootState()
		sdk := sdkBootState.Get()
		require.Nil(t, sdk)

		sdkBootState.Ready(fake.SDKEvaluatorFinder{})

		sdk = sdkBootState.Get()
		require.NotNil(t, sdk)
	})

	t.Run("is ready", func(t *testing.T) {
		sdkBootState := NewSDKBootState()
		sdk := sdkBootState.Get()
		require.Nil(t, sdk)

		require.False(t, sdkBootState.IsReady())

		sdkBootState.Ready(fake.SDKEvaluatorFinder{})

		require.True(t, sdkBootState.IsReady())

		sdk = sdkBootState.Get()
		require.NotNil(t, sdk)
	})

	t.Run("is ready with channel", func(t *testing.T) {
		sdkBootState := NewSDKBootState()
		sdk := sdkBootState.Get()
		require.Nil(t, sdk)

		ch := sdkBootState.IsReadyChan()

		go func() {
			time.Sleep(100 * time.Millisecond)
			sdkBootState.Ready(fake.SDKEvaluatorFinder{})
		}()

		require.True(t, <-ch)
	})

	t.Run("is ready with channel after the first ready sent", func(t *testing.T) {
		sdkBootState := NewSDKBootState()
		sdk := sdkBootState.Get()
		require.Nil(t, sdk)

		sdkBootState.Ready(fake.SDKEvaluatorFinder{})
		ch := sdkBootState.IsReadyChan()
		require.True(t, <-ch)
	})
}
