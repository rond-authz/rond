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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rond-authz/rond/logging"

	"github.com/redis/go-redis/v9"
)

type IRedisClient interface {
	Get(ctx context.Context, key string) (interface{}, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Del(ctx context.Context, key string) error
}

type redisClientCustomBuiltinContextKey struct{}

func WithRedisClient(ctx context.Context, redisClient IRedisClient) context.Context {
	return context.WithValue(ctx, redisClientCustomBuiltinContextKey{}, redisClient)
}

func GetRedisClientFromContext(ctx context.Context) (IRedisClient, error) {
	clientInterface := ctx.Value(redisClientCustomBuiltinContextKey{})
	if clientInterface == nil {
		return nil, nil
	}

	client, ok := clientInterface.(IRedisClient)
	if !ok {
		return nil, fmt.Errorf("no Redis client found in context")
	}
	return client, nil
}

type RedisClient struct {
	client *redis.Client
}

func NewRedisClient(logger logging.Logger, redisClient *redis.Client) (IRedisClient, error) {
	return &RedisClient{client: redisClient}, nil
}

func (redisClient *RedisClient) Get(ctx context.Context, key string) (interface{}, error) {
	log := logging.FromContext(ctx)
	log.WithField("redisKey", key).Debug("performing Redis GET")

	result, err := redisClient.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			log.WithField("redisKey", key).Debug("Redis key not found")
			return nil, nil
		}
		log.WithFields(map[string]any{
			"error":    map[string]any{"message": err.Error()},
			"redisKey": key,
		}).Error("failed Redis GET operation")
		return nil, err
	}

	// Try to parse as JSON first, if it fails return as string
	var parsedValue interface{}
	if err := json.Unmarshal([]byte(result), &parsedValue); err != nil {
		// If JSON parsing fails, return as string
		return result, nil
	}

	return parsedValue, nil
}

func (redisClient *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	log := logging.FromContext(ctx)
	log.WithFields(map[string]any{
		"redisKey":   key,
		"expiration": expiration.String(),
	}).Debug("performing Redis SET")

	// Convert value to JSON string for storage
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	valueToStore := string(jsonBytes)

	err = redisClient.client.Set(ctx, key, valueToStore, expiration).Err()
	if err != nil {
		log.WithFields(map[string]any{
			"error":    map[string]any{"message": err.Error()},
			"redisKey": key,
		}).Error("failed Redis SET operation")
		return err
	}

	return nil
}

func (redisClient *RedisClient) Del(ctx context.Context, key string) error {
	log := logging.FromContext(ctx)
	log.WithField("redisKey", key).Debug("performing Redis DEL")

	deletedCount, err := redisClient.client.Del(ctx, key).Result()
	if err != nil {
		log.WithFields(map[string]any{
			"error":    map[string]any{"message": err.Error()},
			"redisKey": key,
		}).Error("failed Redis DEL operation")
		return err
	}

	log.WithFields(map[string]any{
		"redisKey":     key,
		"deletedCount": deletedCount,
	}).Debug("Redis DEL operation completed")

	return nil
}
