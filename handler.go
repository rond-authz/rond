package main

import (
	"context"
	"net/http"
	"net/http/httputil"

	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
)

const URL_SCHEME = "http"

func rbacHandler(w http.ResponseWriter, req *http.Request) {
	env, err := GetEnv(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no env found in context")
		failResponse(w, "no environment found in context")
		return
	}

	opaEvaluator, err := GetOPAEvaluator(req.Context())
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("no policy evaluator found in context")
		failResponse(w, "no policy evaluator found in context")
		return
	}

	input := map[string]interface{}{
		"request": map[string]interface{}{
			"method":  req.Method,
			"path":    req.URL.Path,
			"headers": req.Header,
			"query":   req.URL.Query(),
		},
	}

	results, err := opaEvaluator.PermissionQuery.Eval(context.TODO(), rego.EvalInput(input))
	if err != nil {
		glogger.Get(req.Context()).WithError(err).Error("policy eval failed")
		failResponse(w, "policy eval failed")
		return
	}

	glogger.Get(req.Context()).WithFields(logrus.Fields{
		"allowed":       results.Allowed(),
		"resultsLength": len(results),
	}).Tracef("policy results")

	if !results.Allowed() {
		glogger.Get(req.Context()).WithError(err).Error("policy resulted in not allowed")
		failResponseWithCode(w, http.StatusForbidden, "RBAC policy evaluation failed")
		return
	}

	targetHostFromEnv := env.TargetServiceHost
	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Host = targetHostFromEnv
			req.URL.Scheme = URL_SCHEME
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
		},
	}
	proxy.ServeHTTP(w, req)
}
