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
	"time"

	"github.com/rond-authz/rond/internal/testutils"
	"github.com/rond-authz/rond/logging"
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

func TestNewRedisClient(t *testing.T) {
	t.Run("creates a new Redis client successfully", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}

		log := logging.NewNoOpLogger()
		redisClient := testutils.GetAndDisposeRedisClient(t)

		client, err := NewRedisClient(log, redisClient)
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestRedisClient_Set_Get_Del(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	log := logging.NewNoOpLogger()
	redisClient := testutils.GetAndDisposeRedisClient(t)

	client, err := NewRedisClient(log, redisClient)
	require.NoError(t, err)
	require.NotNil(t, client)

	ctx := context.Background()

	t.Run("Set and Get string value", func(t *testing.T) {
		key := "test:string"
		value := "hello world"

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value, result)

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Set and Get number value", func(t *testing.T) {
		key := "test:number"
		value := 42

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get value - should be parsed as JSON number
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		// JSON unmarshaling converts numbers to float64
		require.Equal(t, float64(42), result)

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Set and Get boolean value", func(t *testing.T) {
		key := "test:boolean"
		value := true

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value, result)

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Set and Get object value", func(t *testing.T) {
		key := "test:object"
		value := map[string]interface{}{
			"name":   "John Doe",
			"age":    30,
			"active": true,
		}

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.IsType(t, map[string]interface{}{}, result)

		resultMap := result.(map[string]interface{})
		require.Equal(t, "John Doe", resultMap["name"])
		require.Equal(t, float64(30), resultMap["age"]) // JSON numbers are float64
		require.Equal(t, true, resultMap["active"])

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Set and Get array value", func(t *testing.T) {
		key := "test:array"
		value := []interface{}{"apple", "banana", "cherry"}

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.IsType(t, []interface{}{}, result)

		resultArray := result.([]interface{})
		require.Equal(t, 3, len(resultArray))
		require.Equal(t, "apple", resultArray[0])
		require.Equal(t, "banana", resultArray[1])
		require.Equal(t, "cherry", resultArray[2])

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Get non-existent key returns nil", func(t *testing.T) {
		key := "test:nonexistent"

		// Get value that doesn't exist
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("Del non-existent key succeeds", func(t *testing.T) {
		key := "test:nonexistent:del"

		// Delete key that doesn't exist
		err := client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Set with expiration", func(t *testing.T) {
		key := "test:expiring"
		value := "temporary"

		// Set value with 2 second expiration
		err := client.Set(ctx, key, value, 2*time.Second)
		require.NoError(t, err)

		// Get immediately - should exist
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value, result)

		// Wait for expiration
		time.Sleep(3 * time.Second)

		// Get after expiration - should be nil
		result, err = client.Get(ctx, key)
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("Set with zero expiration (no expiration)", func(t *testing.T) {
		key := "test:no-expiration"
		value := "permanent"

		// Set value with no expiration
		err := client.Set(ctx, key, value, 0)
		require.NoError(t, err)

		// Get value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value, result)

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Overwrite existing key", func(t *testing.T) {
		key := "test:overwrite"
		value1 := "first value"
		value2 := "second value"

		// Set first value
		err := client.Set(ctx, key, value1, 10*time.Second)
		require.NoError(t, err)

		// Verify first value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value1, result)

		// Overwrite with second value
		err = client.Set(ctx, key, value2, 10*time.Second)
		require.NoError(t, err)

		// Verify second value
		result, err = client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value2, result)

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})

	t.Run("Del removes key", func(t *testing.T) {
		key := "test:delete"
		value := "to be deleted"

		// Set value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Verify it exists
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, value, result)

		// Delete it
		err = client.Del(ctx, key)
		require.NoError(t, err)

		// Verify it's gone
		result, err = client.Get(ctx, key)
		require.NoError(t, err)
		require.Nil(t, result)
	})

	t.Run("handles nested objects", func(t *testing.T) {
		key := "test:nested"
		value := map[string]interface{}{
			"user": map[string]interface{}{
				"name": "Jane",
				"profile": map[string]interface{}{
					"age":  25,
					"city": "New York",
				},
			},
			"tags": []interface{}{"admin", "user"},
		}

		// Set nested value
		err := client.Set(ctx, key, value, 10*time.Second)
		require.NoError(t, err)

		// Get nested value
		result, err := client.Get(ctx, key)
		require.NoError(t, err)
		require.NotNil(t, result)

		resultMap := result.(map[string]interface{})
		user := resultMap["user"].(map[string]interface{})
		require.Equal(t, "Jane", user["name"])

		profile := user["profile"].(map[string]interface{})
		require.Equal(t, float64(25), profile["age"])
		require.Equal(t, "New York", profile["city"])

		tags := resultMap["tags"].([]interface{})
		require.Equal(t, 2, len(tags))
		require.Equal(t, "admin", tags[0])

		// Cleanup
		err = client.Del(ctx, key)
		require.NoError(t, err)
	})
}
