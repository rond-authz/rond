// Copyright 2025 Mia srl
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

package custom_builtins

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithRedisClientAndGetRedisClientFromContext(t *testing.T) {
	t.Run("stores and retrieves redis client from context", func(t *testing.T) {
		ctx := context.Background()
		originalClient := &RedisClient{}

		// Store client in context
		ctx = WithRedisClient(ctx, originalClient)

		// Retrieve client from context
		retrievedClient, err := GetRedisClientFromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, originalClient, retrievedClient)
	})

	t.Run("returns nil when no redis client is set", func(t *testing.T) {
		ctx := context.Background()

		retrievedClient, err := GetRedisClientFromContext(ctx)
		require.NoError(t, err)
		require.Nil(t, retrievedClient)
	})

	t.Run("returns error when context contains invalid client type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), redisClientCustomBuiltinContextKey{}, "invalid client")

		retrievedClient, err := GetRedisClientFromContext(ctx)
		require.Error(t, err)
		require.ErrorContains(t, err, "no Redis client found in context")
		require.Nil(t, retrievedClient)
	})
}
