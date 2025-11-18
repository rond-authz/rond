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
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/rond-authz/rond/logging"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client   *redis.Client
	database int
}


// NewRedisClient tries to setup a new RedisClient instance.
// The function returns a `nil` client if the environment variable `RedisURL` is not specified.
func NewRedisClient(logger logging.Logger, redisURL string) (*redis.Client, error) {
	if redisURL == "" {
		logger.Info("No Redis configuration provided, skipping setup")
		return nil, nil
	}

	logger.Trace("Start Redis client set up")

	// Parse Redis URL
	parsedURL, err := url.Parse(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed Redis URL validation: %s", err.Error())
	}

	// Extract database number from URL path
	database := 0
	if parsedURL.Path != "" && len(parsedURL.Path) > 1 {
		dbStr := parsedURL.Path[1:] // Remove leading slash
		if db, err := strconv.Atoi(dbStr); err == nil {
			database = db
		}
	}

	// Extract username and password from URL
	username := ""
	password := ""
	if parsedURL.User != nil {
		username = parsedURL.User.Username()
		password, _ = parsedURL.User.Password()
	}

	// Build Redis options
	opts := &redis.Options{
		Addr:     parsedURL.Host,
		Username: username,
		Password: password,
		DB:       database,
	}

	client := redis.NewClient(opts)

	// Test the connection
	ctx, cancelFn := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFn()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("error verifying Redis connection: %s", err.Error())
	}

	logger.Info("Redis client set up completed")
	return client, nil
}
