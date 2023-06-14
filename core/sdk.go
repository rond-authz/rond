package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/internal/metrics"
	"github.com/rond-authz/rond/internal/opatranslator"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/types"
	"github.com/sirupsen/logrus"
)

type PolicyResult struct {
	QueryToProxy []byte
	Allowed      bool
}

type SDK interface {
	Evaluators() PartialResultsEvaluators
	Metrics() metrics.Metrics
	Registry() *prometheus.Registry

	EvaluateRequestPolicy(req *http.Request, userInfo types.User, permission *openapi.RondConfig) (PolicyResult, error)
	// EvaluateResponsePolicy(req *http.Request, userInfo types.User, permission *openapi.RondConfig) (PolicyResult, error)
}

type rondImpl struct {
	evaluator             PartialResultsEvaluators
	logger                *logrus.Entry
	enablePrintStatements bool

	metrics  metrics.Metrics
	registry *prometheus.Registry

	clientTypeHeaderKey string
}

func (r rondImpl) Evaluators() PartialResultsEvaluators {
	return r.evaluator
}

func (r rondImpl) EvaluateRequestPolicy(req *http.Request, userInfo types.User, permission *openapi.RondConfig) (PolicyResult, error) {
	requestContext := req.Context()

	pathParams := mux.Vars(req)
	input, err := InputFromRequest(req, userInfo, r.clientTypeHeaderKey, pathParams, nil)
	if err != nil {
		return PolicyResult{}, err
	}

	regoInput, err := CreateRegoQueryInput(r.logger, input, RegoInputOptions{
		EnableResourcePermissionsMapOptimization: permission.Options.EnableResourcePermissionsMapOptimization,
	})
	if err != nil {
		return PolicyResult{}, nil
	}

	evaluatorOptions := &EvaluatorOptions{
		EnablePrintStatements: r.enablePrintStatements,
	}

	var evaluatorAllowPolicy *OPAEvaluator
	if !permission.RequestFlow.GenerateQuery {
		evaluatorAllowPolicy, err = r.evaluator.GetEvaluatorFromPolicy(requestContext, permission.RequestFlow.PolicyName, regoInput, evaluatorOptions)
		if err != nil {
			return PolicyResult{}, nil
		}
	} else {
		evaluatorAllowPolicy, err = CreateQueryEvaluator(requestContext, r.logger, req, permission.RequestFlow.PolicyName, regoInput, nil, evaluatorOptions)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	_, query, err := evaluatorAllowPolicy.PolicyEvaluation(r.logger, permission)
	if err != nil {
		if errors.Is(err, opatranslator.ErrEmptyQuery) && utils.HasApplicationJSONContentType(req.Header) {
			return PolicyResult{}, err
		}

		r.logger.WithField("error", logrus.Fields{
			"policyName": permission.RequestFlow.PolicyName,
			"message":    err.Error(),
		}).Error("RBAC policy evaluation failed")
		return PolicyResult{}, err
	}

	var queryToProxy = []byte{}
	if query != nil {
		queryToProxy, err = json.Marshal(query)
		if err != nil {
			return PolicyResult{}, err
		}
	}

	return PolicyResult{
		Allowed:      true,
		QueryToProxy: queryToProxy,
	}, nil
}

func (r rondImpl) Metrics() metrics.Metrics {
	return r.metrics
}

func (r rondImpl) Registry() *prometheus.Registry {
	return r.registry
}

func NewSDK(
	ctx context.Context,
	mongoClient types.IMongoClient,
	oas *openapi.OpenAPISpec,
	opaModuleConfig *OPAModuleConfig,
	evaluatorOptions *EvaluatorOptions,
	registry *prometheus.Registry,
) (SDK, error) {
	// TODO: use logger instead of get logger from context
	evaluator, err := SetupEvaluators(ctx, mongoClient, oas, opaModuleConfig, evaluatorOptions)
	if err != nil {
		return nil, err
	}

	m := metrics.SetupMetrics("rond")
	if registry != nil {
		m.MustRegister(registry)
	}

	return rondImpl{
		evaluator: evaluator,

		metrics:  m,
		registry: registry,
	}, nil
}
