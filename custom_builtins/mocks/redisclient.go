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

package mocks

import (
	"context"
	"time"
)

type RedisClientMock struct {
	GetError       error
	GetResult      interface{}
	SetError       error
	DelError       error
	GetExpectation func(key string)
	SetExpectation func(key string, value interface{}, expiration time.Duration)
	DelExpectation func(key string)
}

func (redisClient RedisClientMock) Get(ctx context.Context, key string) (interface{}, error) {
	if redisClient.GetExpectation != nil {
		redisClient.GetExpectation(key)
	}
	if redisClient.GetError != nil {
		return nil, redisClient.GetError
	}

	return redisClient.GetResult, nil
}

func (redisClient RedisClientMock) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	if redisClient.SetExpectation != nil {
		redisClient.SetExpectation(key, value, expiration)
	}
	if redisClient.SetError != nil {
		return redisClient.SetError
	}

	return nil
}

func (redisClient RedisClientMock) Del(ctx context.Context, key string) error {
	if redisClient.DelExpectation != nil {
		redisClient.DelExpectation(key)
	}
	if redisClient.DelError != nil {
		return redisClient.DelError
	}

	return nil
}
