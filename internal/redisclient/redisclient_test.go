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
	"context"
	"testing"
	"time"

	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"
	"github.com/stretchr/testify/require"
)

func TestSetupRedisClient(t *testing.T) {

	t.Run("if RedisURL empty, returns nil", func(t *testing.T) {
		log := logging.NewNoOpLogger()
		client, err := NewRedisClient(log, "")
		require.NoError(t, err)
		require.True(t, client == nil, "RedisURL is nil")
	})

	t.Run("throws if redis url is not valid", func(t *testing.T) {
		redisURL := "://invalid-url-with-no-scheme"

		log := logging.NewNoOpLogger()
		client, err := NewRedisClient(log, redisURL)
		require.True(t, err != nil, "setup redis not returns error")
		require.Contains(t, err.Error(), "failed Redis URL validation:")
		require.True(t, client == nil)
	})

	t.Run("throws if redis connection fails", func(t *testing.T) {
		// Use a host that won't be reachable to ensure connection failure
		redisURL := "redis://invalid-host-that-does-not-exist:6379/0"

		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.Error(t, err, "setup redis should return error")
		require.Contains(t, err.Error(), "error verifying Redis connection:")
		require.Nil(t, client)
	})
}

func TestRedisClientIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("successfully connects to Redis with valid URL", func(t *testing.T) {
		redisURL := testutils.GetRedisURL(t)
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.NoError(t, err)
		require.NotNil(t, client)

		// Test basic operations
		ctx := context.Background()
		err = client.Set(ctx, "test:integration", "hello", 10*time.Second)
		require.NoError(t, err)

		val, err := client.Get(ctx, "test:integration")
		require.NoError(t, err)
		require.Equal(t, "hello", val)

		// Cleanup
		_, err = client.Del(ctx, "test:integration")
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)
	})

	t.Run("successfully connects with custom connection options", func(t *testing.T) {
		redisHost := testutils.GetRedisHost(t)
		redisURL := testutils.FormatRedisURL(redisHost, 1)
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.NoError(t, err)
		require.NotNil(t, client)

		// Test connection works
		ctx := context.Background()
		err = client.Ping(ctx)
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)
	})

	t.Run("successfully connects with authentication in URL", func(t *testing.T) {
		// Test with password authentication
		// Redis auth instance runs on port 6380 with password "testpassword123"
		redisURL := "redis://:testpassword123@localhost:6380/0"
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.NoError(t, err)
		require.NotNil(t, client)

		ctx := context.Background()
		err = client.Ping(ctx)
		require.NoError(t, err)

		// Test that we can actually use the authenticated connection
		err = client.Set(ctx, "test:auth", "authenticated", 10*time.Second)
		require.NoError(t, err)

		val, err := client.Get(ctx, "test:auth")
		require.NoError(t, err)
		require.Equal(t, "authenticated", val)

		// Cleanup
		_, err = client.Del(ctx, "test:auth")
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)
	})

	t.Run("fails to connect with wrong password", func(t *testing.T) {
		// Test with incorrect password
		redisURL := "redis://:wrongpassword@localhost:6380/0"
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error verifying Redis connection:")
		require.Nil(t, client)
	})

	t.Run("fails to connect without password when required", func(t *testing.T) {
		// Test connecting to auth-required Redis without password
		redisURL := "redis://localhost:6380/0"
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error verifying Redis connection:")
		require.Nil(t, client)
	})

	t.Run("successfully connects with username and password in URL", func(t *testing.T) {
		// Redis 6+ supports ACL with username:password
		// For testing purposes with Redis 7, we use default user with password
		redisURL := "redis://default:testpassword123@localhost:6380/0"
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.NoError(t, err)
		require.NotNil(t, client)

		ctx := context.Background()
		err = client.Ping(ctx)
		require.NoError(t, err)

		err = client.Close()
		require.NoError(t, err)
	})

	t.Run("handles different database numbers", func(t *testing.T) {
		redisHost := testutils.GetRedisHost(t)
		log := logging.NewNoOpLogger()

		// Test with database 0
		redisURL0 := testutils.FormatRedisURL(redisHost, 0)
		client0, err := NewRedisClient(log, redisURL0)
		require.NoError(t, err)
		require.NotNil(t, client0)

		// Test with database 1
		redisURL1 := testutils.FormatRedisURL(redisHost, 1)
		client1, err := NewRedisClient(log, redisURL1)
		require.NoError(t, err)
		require.NotNil(t, client1)

		// Set same key in different databases
		ctx := context.Background()
		err = client0.Set(ctx, "test:db", "db0", 10*time.Second)
		require.NoError(t, err)

		err = client1.Set(ctx, "test:db", "db1", 10*time.Second)
		require.NoError(t, err)

		// Verify they're different
		val0, err := client0.Get(ctx, "test:db")
		require.NoError(t, err)
		require.Equal(t, "db0", val0)

		val1, err := client1.Get(ctx, "test:db")
		require.NoError(t, err)
		require.Equal(t, "db1", val1)

		// Cleanup
		_, err = client0.Del(ctx, "test:db")
		require.NoError(t, err)
		_, err = client1.Del(ctx, "test:db")
		require.NoError(t, err)

		err = client0.Close()
		require.NoError(t, err)
		err = client1.Close()
		require.NoError(t, err)
	})

	t.Run("handles Redis operations correctly", func(t *testing.T) {
		redisURL := testutils.GetRedisURL(t)
		log := logging.NewNoOpLogger()

		client, err := NewRedisClient(log, redisURL)
		require.NoError(t, err)
		require.NotNil(t, client)
		defer client.Close()

		ctx := context.Background()

		// Test SET and GET
		err = client.Set(ctx, "test:string", "hello world", 0)
		require.NoError(t, err)

		val, err := client.Get(ctx, "test:string")
		require.NoError(t, err)
		require.Equal(t, "hello world", val)

		// Test DELETE
		deleted, err := client.Del(ctx, "test:string")
		require.NoError(t, err)
		require.Equal(t, int64(1), deleted)

		// Test key doesn't exist after delete
		_, err = client.Get(ctx, "test:string")
		require.Error(t, err)

		// Test EXPIRE - set a key with expiration
		err = client.Set(ctx, "test:expire", "temp", 1*time.Second)
		require.NoError(t, err)

		// Verify key exists
		val, err = client.Get(ctx, "test:expire")
		require.NoError(t, err)
		require.Equal(t, "temp", val)

		// Wait for expiration
		time.Sleep(2 * time.Second)

		// Verify key is gone
		_, err = client.Get(ctx, "test:expire")
		require.Error(t, err)
	})
}
