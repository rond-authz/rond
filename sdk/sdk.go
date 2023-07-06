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

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/openapi"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type rondImpl struct {
	evaluatorOptions *core.EvaluatorOptions
	opaModuleConfig  *core.OPAModuleConfig
}

type Options struct {
	Registry         *prometheus.Registry
	EvaluatorOptions *core.EvaluatorOptions
}

type Rond interface {
	// WithConfig(rondConfig openapi.RondConfig, options *WithConfigOptions) Evaluator
	FromOAS(ctx context.Context, oas *openapi.OpenAPISpec, options *FromOASOptions) (OpenAPI, error)
}

type WithConfigOptions struct {
	Logger           *logrus.Entry
	EvaluatorOptions core.EvaluatorOptions
}

// func (r rondImpl) WithConfig(rondConfig openapi.RondConfig, options *WithConfigOptions) Evaluator {
// 	if options == nil {
// 		options = &WithConfigOptions{}
// 	}
// 	// TODO: default to a logger instead of panic
// 	if options.Logger == nil {
// 		panic(fmt.Errorf("logger must be set in config options"))
// 	}
// 	return evaluator{
// 		rondConfig:       rondConfig,
// 		logger:           options.Logger,
// 		opaModuleConfig:  r.opaModuleConfig,
// 		evaluatorOptions: &options.EvaluatorOptions,
// 	}
// }

type FromOASOptions struct {
	Logger *logrus.Entry
}

func (r rondImpl) FromOAS(ctx context.Context, oas *openapi.OpenAPISpec, options *FromOASOptions) (OpenAPI, error) {
	if options == nil || options.Logger == nil {
		// TODO: default to a logger instead of return error
		return nil, fmt.Errorf("logger is required inside options")
	}
	logger := options.Logger
	evaluator, err := core.SetupEvaluators(ctx, logger, oas, r.opaModuleConfig, r.evaluatorOptions)
	if err != nil {
		return nil, err
	}

	logger.WithField("policiesLength", len(evaluator)).Debug("policies evaluators partial results computed")

	oasRouter, err := oas.PrepareOASRouter()
	if err != nil {
		return nil, fmt.Errorf("invalid OAS configuration: %s", err)
	}

	return oasImpl{
		oas:       oas,
		oasRouter: oasRouter,

		opaModuleConfig:         r.opaModuleConfig,
		partialResultEvaluators: evaluator,
		evaluatorOptions:        r.evaluatorOptions,
	}, nil
}

// The SDK is now into core because there are coupled function here which should use the SDK itself
// (which uses core, so it will result in a cyclic dependency). In the future, sdk should be in a
// specific package.
func New(opaModuleConfig *core.OPAModuleConfig, options *Options) (Rond, error) {
	if opaModuleConfig == nil {
		return nil, fmt.Errorf("OPAModuleConfig must not be nil")
	}

	if options == nil {
		options = &Options{}
	}
	m := metrics.SetupMetrics("rond")
	if options.Registry != nil {
		m.MustRegister(options.Registry)
	}
	evaluatorOptions := &core.EvaluatorOptions{}
	if options.EvaluatorOptions != nil {
		evaluatorOptions = options.EvaluatorOptions
	}
	evaluatorOptions.WithMetrics(m)

	return rondImpl{
		evaluatorOptions: evaluatorOptions,
		opaModuleConfig:  opaModuleConfig,
	}, nil
}
