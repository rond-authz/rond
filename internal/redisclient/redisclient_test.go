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

package redisclient

import (
	"testing"

	"github.com/rond-authz/rond/logging"
	"github.com/stretchr/testify/require"
)

func TestSetupRedisClient(t *testing.T) {
	connOptions := ConnectionOpts{}

	t.Run("if RedisURL empty, returns nil", func(t *testing.T) {
		log := logging.NewNoOpLogger()
		client, err := NewRedisClient(log, "", connOptions)
		require.NoError(t, err)
		require.True(t, client == nil, "RedisURL is nil")
	})

	t.Run("throws if redis url is not valid", func(t *testing.T) {
		redisURL := "://invalid-url-with-no-scheme"

		log := logging.NewNoOpLogger()
		client, err := NewRedisClient(log, redisURL, connOptions)
		require.True(t, err != nil, "setup redis not returns error")
		require.Contains(t, err.Error(), "failed Redis URL validation:")
		require.True(t, client == nil)
	})

	t.Run("throws if redis connection fails", func(t *testing.T) {
		redisURL := "not-valid-redis-url"

		log := logging.NewNoOpLogger()
		client, err := NewRedisClient(log, redisURL, connOptions)
		require.Error(t, err, "setup redis should return error")
		require.Contains(t, err.Error(), "error verifying Redis connection:")
		require.Nil(t, client)
	})

	// Note: For integration tests, we would need a real Redis instance
	// These tests focus on configuration validation rather than actual connections
}
