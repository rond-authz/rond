package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
)

type OPAModuleConfig struct {
	Name    string
	Content string
}

type Evaluator interface {
	Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error)
}

// TODO: This should be transformed to a map having as keys the API VERB+PATH
// and as content a struct with permssions and the actual opa query eval
type OPAEvaluator struct {
	PermissionQuery Evaluator
}

type OPAEvaluatorKey struct{}

type TruthyEvaluator struct{}

func (e *TruthyEvaluator) Eval(ctx context.Context, options ...rego.EvalOption) (rego.ResultSet, error) {
	return rego.ResultSet{
		rego.Result{
			Expressions: []*rego.ExpressionValue{
				{Value: true},
			},
		},
	}, nil
}

func OPAMiddleware(opaModuleConfig *OPAModuleConfig, openAPISpec *OpenAPISpec, envs *EnvironmentVariables) mux.MiddlewareFunc {
	// TODO: build a map as { [verb+path]: permission }
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.RequestURI(), "/-/") {
				next.ServeHTTP(w, r)
				return
			}

			permission, err := openAPISpec.getPermissionsFromRequest(r)
			if err != nil && r.Method == http.MethodGet && r.URL.Path == envs.TargetServiceOASPath {
				evaluator := &OPAEvaluator{PermissionQuery: &TruthyEvaluator{}}
				ctx := context.WithValue(r.Context(), OPAEvaluatorKey{}, evaluator)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			if err != nil || permission.AllowPermission == "" {
				fields := logrus.Fields{
					"originalRequestPath": r.URL.Path,
					"method":              r.Method,
					"allowPermission":     permission.AllowPermission,
				}
				if err != nil {
					fields["error"] = logrus.Fields{"message": err.Error()}
				}
				errorMessage := "The request doesn't match any known API"
				glogger.Get(r.Context()).WithFields(fields).Errorf(errorMessage)
				failResponseWithCode(w, http.StatusForbidden, errorMessage)
				return
			}

			queryString := fmt.Sprintf("data.example.%s", permission.AllowPermission)
			query, err := rego.New(
				rego.Query(queryString),
				rego.Module(opaModuleConfig.Name, opaModuleConfig.Content),
			).PrepareForEval(context.TODO())

			if err != nil {
				glogger.Get(r.Context()).WithError(err).Error("failed RBAC policy creation")
				failResponse(w, err.Error())
				return
			}

			evaluator := &OPAEvaluator{query}
			ctx := context.WithValue(r.Context(), OPAEvaluatorKey{}, evaluator)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func loadRegoModule(rootDirectory string) (*OPAModuleConfig, error) {
	var regoModulePath string
	filepath.Walk(rootDirectory, func(path string, info os.FileInfo, err error) error {
		if regoModulePath != "" {
			return nil
		}

		if filepath.Ext(path) == ".rego" {
			regoModulePath = path
		}
		return nil
	})

	if regoModulePath == "" {
		return nil, fmt.Errorf("no rego module found in directory")
	}
	fileContent, err := ioutil.ReadFile(regoModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed rego file read")
	}

	return &OPAModuleConfig{
		Name:    filepath.Base(regoModulePath),
		Content: string(fileContent),
	}, nil
}

// GetOPAEvaluator can be used by a request handler to get OPAEvalutor instance from its context.
func GetOPAEvaluator(requestContext context.Context) (*OPAEvaluator, error) {
	opaEvaluator, ok := requestContext.Value(OPAEvaluatorKey{}).(*OPAEvaluator)
	if !ok {
		return nil, fmt.Errorf("no evaluator found in request context")
	}

	return opaEvaluator, nil
}

var (
	ErrRequestFailed  = errors.New("request failed")
	ErrFileLoadFailed = errors.New("file loading failed")
)
