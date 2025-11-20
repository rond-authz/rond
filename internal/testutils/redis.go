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

package testutils

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const LocalhostRedis = "localhost:6379"

// GetRedisHost returns the Redis host to use in tests.
// It checks the REDIS_HOST_CI environment variable first, falling back to localhost.
func GetRedisHost(t testing.TB) string {
	t.Helper()

	redisHost := os.Getenv("REDIS_HOST_CI")
	if redisHost == "" {
		redisHost = LocalhostRedis
		t.Logf("Connection to localhost Redis, on CI env this is a problem!")
	}
	return redisHost
}

// FormatRedisURL formats a Redis URL from host and database number
func FormatRedisURL(redisHost string, db int) string {
	return fmt.Sprintf("redis://%s/%d", redisHost, db)
}

// GetRedisURL returns a Redis URL with a random database number
func GetRedisURL(t *testing.T) string {
	return FormatRedisURL(GetRedisHost(t), 0)
}

// GetAndDisposeRedisClient creates a Redis client and registers cleanup
func GetAndDisposeRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	redisHost := GetRedisHost(t)
	client := redis.NewClient(&redis.Options{
		Addr: redisHost,
		DB:   0,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Ping(ctx).Err()
	require.NoError(t, err, "failed redis connection")

	t.Cleanup(func() {
		// Flush all keys from the test database
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.FlushDB(ctx).Err(); err != nil {
			t.Logf("redis flush failed: %s", err.Error())
		}
		if err := client.Close(); err != nil {
			t.Logf("redis disconnect failed: %s", err.Error())
		}
	})

	return client
}

// PopulateRedisForTesting populates Redis with test data
func PopulateRedisForTesting(t *testing.T, ctx context.Context, client *redis.Client) {
	t.Helper()

	// Set some test keys
	testData := map[string]string{
		"test:key1": "value1",
		"test:key2": "value2",
		"test:key3": "value3",
	}

	for key, value := range testData {
		err := client.Set(ctx, key, value, 0).Err()
		require.NoError(t, err, "failed to set redis key")
	}

	// Set some keys with expiration
	err := client.Set(ctx, "test:expiring", "temp_value", 10*time.Second).Err()
	require.NoError(t, err, "failed to set expiring redis key")
}
