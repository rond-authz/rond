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
	"errors"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/rond-authz/rond/custom_builtins/mocks"
	"github.com/stretchr/testify/require"
)

func prepareRedisContext(t *testing.T, redisClientMock *mocks.RedisClientMock) rego.BuiltinContext {
	t.Helper()

	ctx := context.Background()

	if redisClientMock != nil {
		ctx = WithRedisClient(ctx, redisClientMock)
	}

	return rego.BuiltinContext{
		Context: ctx,
	}
}

func TestRedisGetDefinition(t *testing.T) {
	defaultMock := &mocks.RedisClientMock{}

	t.Run("returns error if redis client is not set", func(t *testing.T) {
		_, err := redisGetDef(
			prepareRedisContext(t, nil),
			nil,
		)
		require.ErrorContains(t, err, "redis client not set")
	})

	t.Run("returns error if redis client in context is not valid", func(t *testing.T) {
		_, err := redisGetDef(
			rego.BuiltinContext{
				Context: context.WithValue(context.Background(), redisClientCustomBuiltinContextKey{}, "not a valid client"),
			},
			nil,
		)
		require.ErrorContains(t, err, "no Redis client found in context")
	})

	t.Run("returns error if key is not a string", func(t *testing.T) {
		_, err := redisGetDef(
			prepareRedisContext(t, defaultMock),
			ast.BooleanTerm(false),
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns error if Get returns an error", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			GetError: errors.New("some error"),
			GetExpectation: func(key string) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
			},
		}
		_, err := redisGetDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
		)
		require.ErrorContains(t, err, "some error")
		require.True(t, assertionInvoked)
	})

	t.Run("returns value when Get is successful", func(t *testing.T) {
		assertionInvoked := false
		expectedResult := map[string]interface{}{"test": "value"}
		mock := &mocks.RedisClientMock{
			GetResult: expectedResult,
			GetExpectation: func(key string) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
			},
		}
		result, err := redisGetDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
		)
		require.NoError(t, err)
		require.True(t, assertionInvoked)

		var actualResult map[string]interface{}
		require.NoError(t, ast.As(result.Value, &actualResult))
		require.Equal(t, expectedResult, actualResult)
	})
}

func TestRedisSetDefinition(t *testing.T) {
	defaultMock := &mocks.RedisClientMock{}

	t.Run("returns error if redis client is not set", func(t *testing.T) {
		_, err := redisSetDef(
			prepareRedisContext(t, nil),
			nil,
			nil,
		)
		require.ErrorContains(t, err, "redis client not set")
	})

	t.Run("returns error if redis client in context is not valid", func(t *testing.T) {
		_, err := redisSetDef(
			rego.BuiltinContext{
				Context: context.WithValue(context.Background(), redisClientCustomBuiltinContextKey{}, "not a valid client"),
			},
			nil,
			nil,
		)
		require.ErrorContains(t, err, "no Redis client found in context")
	})

	t.Run("returns error if key is not a string", func(t *testing.T) {
		_, err := redisSetDef(
			prepareRedisContext(t, defaultMock),
			ast.BooleanTerm(false),
			ast.StringTerm("value"),
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns error if Set returns an error", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			SetError: errors.New("some error"),
			SetExpectation: func(key string, value interface{}, expiration time.Duration) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
				require.Equal(t, "test-value", value)
				require.Equal(t, time.Duration(0), expiration)
			},
		}
		_, err := redisSetDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
			ast.StringTerm("test-value"),
		)
		require.ErrorContains(t, err, "some error")
		require.True(t, assertionInvoked)
	})

	t.Run("returns true when Set is successful", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			SetExpectation: func(key string, value interface{}, expiration time.Duration) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
				require.Equal(t, "test-value", value)
				require.Equal(t, time.Duration(0), expiration)
			},
		}
		result, err := redisSetDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
			ast.StringTerm("test-value"),
		)
		require.NoError(t, err)
		require.True(t, assertionInvoked)

		var actualResult bool
		require.NoError(t, ast.As(result.Value, &actualResult))
		require.True(t, actualResult)
	})
}

func TestRedisSetWithExpirationDefinition(t *testing.T) {
	defaultMock := &mocks.RedisClientMock{}

	t.Run("returns error if redis client is not set", func(t *testing.T) {
		_, err := redisSetWithExpirationDef(
			prepareRedisContext(t, nil),
			nil,
			nil,
			nil,
		)
		require.ErrorContains(t, err, "redis client not set")
	})

	t.Run("returns error if expiration is not a number", func(t *testing.T) {
		_, err := redisSetWithExpirationDef(
			prepareRedisContext(t, defaultMock),
			ast.StringTerm("test-key"),
			ast.StringTerm("test-value"),
			ast.BooleanTerm(false),
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns true when Set with expiration is successful", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			SetExpectation: func(key string, value interface{}, expiration time.Duration) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
				require.Equal(t, "test-value", value)
				require.Equal(t, 60*time.Second, expiration)
			},
		}
		result, err := redisSetWithExpirationDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
			ast.StringTerm("test-value"),
			ast.IntNumberTerm(60),
		)
		require.NoError(t, err)
		require.True(t, assertionInvoked)

		var actualResult bool
		require.NoError(t, ast.As(result.Value, &actualResult))
		require.True(t, actualResult)
	})
}

func TestRedisDelDefinition(t *testing.T) {
	defaultMock := &mocks.RedisClientMock{}

	t.Run("returns error if redis client is not set", func(t *testing.T) {
		_, err := redisDelDef(
			prepareRedisContext(t, nil),
			nil,
		)
		require.ErrorContains(t, err, "redis client not set")
	})

	t.Run("returns error if redis client in context is not valid", func(t *testing.T) {
		_, err := redisDelDef(
			rego.BuiltinContext{
				Context: context.WithValue(context.Background(), redisClientCustomBuiltinContextKey{}, "not a valid client"),
			},
			nil,
		)
		require.ErrorContains(t, err, "no Redis client found in context")
	})

	t.Run("returns error if key is not a string", func(t *testing.T) {
		_, err := redisDelDef(
			prepareRedisContext(t, defaultMock),
			ast.BooleanTerm(false),
		)
		require.ErrorContains(t, err, "cannot unmarshal bool")
	})

	t.Run("returns error if Del returns an error", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			DelError: errors.New("some error"),
			DelExpectation: func(key string) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
			},
		}
		_, err := redisDelDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
		)
		require.ErrorContains(t, err, "some error")
		require.True(t, assertionInvoked)
	})

	t.Run("returns true when Del is successful", func(t *testing.T) {
		assertionInvoked := false
		mock := &mocks.RedisClientMock{
			DelExpectation: func(key string) {
				assertionInvoked = true
				require.Equal(t, "test-key", key)
			},
		}
		result, err := redisDelDef(
			prepareRedisContext(t, mock),
			ast.StringTerm("test-key"),
		)
		require.NoError(t, err)
		require.True(t, assertionInvoked)

		var actualResult bool
		require.NoError(t, ast.As(result.Value, &actualResult))
		require.True(t, actualResult)
	})
}
