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

package sdk

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/mocks"
	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/metrics"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestNewFromOas(t *testing.T) {
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		very_very_composed_permission { true }`,
	}
	ctx := context.Background()

	openAPISpec, err := openapi.LoadOASFile("../mocks/simplifiedMock.json")
	require.NoError(t, err)

	logger := logging.NewNoOpLogger()
	options := &Options{
		Logger: logger,
	}

	t.Run("throws if opaModuleConfig is nil", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, nil, nil, options)
		require.EqualError(t, err, "OPAModuleConfig must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("throws if oas is nil", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, opaModule, nil, options)
		require.EqualError(t, err, "oas must not be nil")
		require.Nil(t, sdk)
	})

	t.Run("throws if oas is invalid", func(t *testing.T) {
		oas, err := openapi.LoadOASFile("../mocks/invalidOASConfiguration.json")
		require.NoError(t, err)
		sdk, err := NewFromOAS(ctx, opaModule, oas, options)
		require.ErrorContains(t, err, "invalid OAS configuration:")
		require.Nil(t, sdk)
	})

	t.Run("if metrics is passed, setup metrics", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, opaModule, openAPISpec, &Options{
			Metrics: metrics.NoOpMetrics(),
			Logger:  logger,
		})
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
	})

	t.Run("passes EvaluatorOptions and set metrics correctly", func(t *testing.T) {
		evalOpts := &core.OPAEvaluatorOptions{
			EnablePrintStatements: true,
		}
		sdk, err := NewFromOAS(ctx, opaModule, openAPISpec, &Options{
			EvaluatorOptions: evalOpts,
			Logger:           logger,
			Metrics:          metrics.NoOpMetrics(),
		})
		require.NoError(t, err)
		require.NotEmpty(t, sdk)
		r, ok := sdk.(oasImpl)
		require.True(t, ok)
		require.Equal(t, evalOpts, r.opaEvaluatorOptions)
	})

	t.Run("creates OAS sdk correctly", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, opaModule, openAPISpec, options)
		require.NoError(t, err)

		t.Run("and find evaluators", func(t *testing.T) {
			evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			require.NotNil(t, evaluator)
		})
	})

	t.Run("ok if options is nil", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, opaModule, openAPISpec, nil)
		require.NoError(t, err)
		require.NotNil(t, sdk)

		t.Run("and find evaluators", func(t *testing.T) {
			evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			require.NotNil(t, evaluator)
		})
	})

	t.Run("ok if logger is nil", func(t *testing.T) {
		sdk, err := NewFromOAS(ctx, opaModule, openAPISpec, &Options{})
		require.NoError(t, err)
		require.NotNil(t, sdk)

		t.Run("and find evaluators", func(t *testing.T) {
			evaluator, err := sdk.FindEvaluator(logger, http.MethodGet, "/users/")
			require.NoError(t, err)
			require.NotNil(t, evaluator)
		})
	})
}

func TestNewWithConfig(t *testing.T) {
	opaModule := &core.OPAModuleConfig{
		Name: "example.rego",
		Content: `package policies
		allow { true }
		projection_field { true }
		`,
	}
	ctx := context.Background()

	logger := logging.NewNoOpLogger()
	options := &Options{
		Logger: logger,
	}

	rondConfig := core.RondConfig{
		RequestFlow:  core.RequestFlow{PolicyName: "allow"},
		ResponseFlow: core.ResponseFlow{PolicyName: "projection_field"},
	}

	t.Run("throws if empty config", func(t *testing.T) {
		evaluator, err := NewWithConfig(ctx, opaModule, core.RondConfig{}, options)
		require.ErrorContains(t, err, core.ErrInvalidConfig.Error())
		require.Nil(t, evaluator)
	})

	t.Run("throws if opaModuleConfig is nil", func(t *testing.T) {
		sdk, err := NewWithConfig(ctx, nil, rondConfig, options)
		require.EqualError(t, err, fmt.Sprintf("%s: OPAModuleConfig must not be nil", core.ErrEvaluatorCreationFailed))
		require.Nil(t, sdk)
	})

	t.Run("ok with nil options", func(t *testing.T) {
		evaluator, err := NewWithConfig(ctx, opaModule, rondConfig, nil)
		require.NoError(t, err)
		require.NotNil(t, evaluator)

		t.Run("run evaluator correctly", func(t *testing.T) {
			result, err := evaluator.EvaluateRequestPolicy(ctx, getFakeInput(t, core.InputRequest{}, ""), types.User{})
			require.NoError(t, err)
			require.Equal(t, PolicyResult{
				Allowed:      true,
				QueryToProxy: []byte(""),
			}, result)
		})
	})

	t.Run("ok if logger not passed", func(t *testing.T) {
		evaluator, err := NewWithConfig(ctx, opaModule, rondConfig, nil)
		require.NoError(t, err)
		require.NotNil(t, evaluator)

		t.Run("run evaluator correctly", func(t *testing.T) {
			result, err := evaluator.EvaluateRequestPolicy(ctx, getFakeInput(t, core.InputRequest{}, ""), types.User{})
			require.NoError(t, err)
			require.Equal(t, PolicyResult{
				Allowed:      true,
				QueryToProxy: []byte(""),
			}, result)
		})
	})

	t.Run("passes EvaluatorOptions and set metrics correctly", func(t *testing.T) {
		evalOpts := &core.OPAEvaluatorOptions{
			EnablePrintStatements: true,
		}
		eval, err := NewWithConfig(ctx, opaModule, rondConfig, &Options{
			EvaluatorOptions: evalOpts,
			Metrics:          metrics.NoOpMetrics(),
			Logger:           logger,
		})
		require.NoError(t, err)
		require.NotEmpty(t, eval)
		r, ok := eval.(evaluator)
		require.True(t, ok)
		require.Equal(t, evalOpts, r.opaEvaluatorOptions)
	})

	t.Run("creates config sdk correctly", func(t *testing.T) {
		evaluator, err := NewWithConfig(ctx, opaModule, rondConfig, options)
		require.NoError(t, err)
		require.NotNil(t, evaluator)

		t.Run("run evaluator correctly", func(t *testing.T) {
			result, err := evaluator.EvaluateRequestPolicy(ctx, getFakeInput(t, core.InputRequest{}, ""), types.User{})
			require.NoError(t, err)
			require.Equal(t, PolicyResult{
				Allowed:      true,
				QueryToProxy: []byte(""),
			}, result)
		})
	})

	t.Run("creates config sdk correctly - using mongo functions", func(t *testing.T) {
		opaModule := &core.OPAModuleConfig{
			Name: "example.rego",
			Content: `package policies
			allow {
				project := find_one("my-collection", {"myField": "1234"})
				project.myField == "1234"
			}
			projection_field { true }
			`,
		}
		options := &Options{
			Logger: logger,
			EvaluatorOptions: &core.OPAEvaluatorOptions{
				MongoClient: mocks.MongoClientMock{
					FindOneResult: map[string]string{"myField": "1234"},
					FindOneExpectation: func(collectionName string, query interface{}) {
						require.Equal(t, "my-collection", collectionName)
						require.Equal(t, map[string]interface{}{"myField": "1234"}, query)
					},
				},
			},
		}

		evaluator, err := NewWithConfig(ctx, opaModule, rondConfig, options)
		require.NoError(t, err)
		require.NotNil(t, evaluator)

		t.Run("run evaluator correctly", func(t *testing.T) {
			result, err := evaluator.EvaluateRequestPolicy(ctx, getFakeInput(t, core.InputRequest{}, ""), types.User{})
			require.NoError(t, err)
			require.Equal(t, PolicyResult{
				Allowed:      true,
				QueryToProxy: []byte(""),
			}, result)
		})
	})
}

type sdkOptions struct {
	opaModuleContent string
	oasFilePath      string

	mongoClient types.IMongoClient
	metrics     *metrics.Metrics
}

type tHelper interface {
	Helper()
}

type FakeInput struct {
	request    core.InputRequest
	clientType string
}

func (i FakeInput) Input(user types.User, responseBody any) (core.Input, error) {
	return core.Input{
		User: core.InputUser{
			ID:         user.UserID,
			Properties: user.Properties,
			Groups:     user.UserGroups,
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
		},
		Request: i.request,
		Response: core.InputResponse{
			Body: responseBody,
		},
		ClientType: i.clientType,
	}, nil
}

func getFakeInput(t require.TestingT, request core.InputRequest, clientType string) core.RondInput {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	return FakeInput{
		request:    request,
		clientType: clientType,
	}
}
