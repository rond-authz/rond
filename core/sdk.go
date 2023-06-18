package core

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bunrouter"
)

type PolicyResult struct {
	QueryToProxy []byte
	Allowed      bool
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Does not use outside this repository until it is not ready.
type SDK interface {
	Metrics() metrics.Metrics

	FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error)
	EvaluatorFromConfig(logger *logrus.Entry, config openapi.RondConfig) SDKEvaluator
}

// Warning: This interface is experimental, and it could change with breaking also in rond patches.
// Does not use outside this repository until it is not ready.
type SDKEvaluator interface {
	Permission() openapi.RondConfig
	PartialResultsEvaluators() PartialResultsEvaluators
}

type evaluator struct {
	rond       rondImpl
	logger     *logrus.Entry
	rondConfig openapi.RondConfig
}

func (e evaluator) Permission() openapi.RondConfig {
	return e.rondConfig
}

func (e evaluator) PartialResultsEvaluators() PartialResultsEvaluators {
	return e.rond.evaluator
}

type rondImpl struct {
	evaluator        PartialResultsEvaluators
	evaluatorOptions *EvaluatorOptions
	oasRouter        *bunrouter.CompatRouter
	oas              *openapi.OpenAPISpec

	metrics  metrics.Metrics
	registry *prometheus.Registry

	clientTypeHeaderKey string
}

func (r rondImpl) FindEvaluator(logger *logrus.Entry, method, path string) (SDKEvaluator, error) {
	permission, err := r.oas.FindPermission(r.oasRouter, path, method)
	return evaluator{
		rondConfig: permission,
		logger:     logger,
		rond:       r,
	}, err
}

func (r rondImpl) EvaluatorFromConfig(logger *logrus.Entry, config openapi.RondConfig) SDKEvaluator {
	return evaluator{
		rondConfig: config,
		logger:     logger,
		rond:       r,
	}
}

func (r rondImpl) Metrics() metrics.Metrics {
	return r.metrics
}

func (r rondImpl) Registry() *prometheus.Registry {
	return r.registry
}

func NewSDK(
	ctx context.Context,
	logger *logrus.Entry,
	mongoClient types.IMongoClient,
	oas *openapi.OpenAPISpec,
	opaModuleConfig *OPAModuleConfig,
	evaluatorOptions *EvaluatorOptions,
	registry *prometheus.Registry,
	clientTypeHeaderKey string,
) (SDK, error) {
	// TODO: use logger instead of get logger from context
	evaluator, err := SetupEvaluators(ctx, mongoClient, oas, opaModuleConfig, evaluatorOptions)
	if err != nil {
		return nil, err
	}

	logger.WithField("policiesLength", len(evaluator)).Debug("policies evaluators partial results computed")

	oasRouter := oas.PrepareOASRouter()

	m := metrics.SetupMetrics("rond")
	if registry != nil {
		m.MustRegister(registry)
	}

	return rondImpl{
		evaluator:        evaluator,
		oasRouter:        oasRouter,
		evaluatorOptions: evaluatorOptions,
		oas:              oas,

		metrics:  m,
		registry: registry,

		clientTypeHeaderKey: clientTypeHeaderKey,
	}, nil
}

type sdkKey struct{}

func WithEvaluatorSKD(ctx context.Context, evaluator SDKEvaluator) context.Context {
	return context.WithValue(ctx, sdkKey{}, evaluator)
}

func GetEvaluatorSKD(ctx context.Context) (SDKEvaluator, error) {
	sdk, ok := ctx.Value(sdkKey{}).(SDKEvaluator)
	if !ok {
		return nil, fmt.Errorf("no SDKEvaluator found in request context")
	}

	return sdk, nil
}
