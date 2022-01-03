package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"github.com/sirupsen/logrus"
)

var (
	ErrRequestFailed  = errors.New("request failed")
	ErrFileLoadFailed = errors.New("file loading failed")
)

type OPAModuleConfig struct {
	Name    string
	Content string
}

type OPAEvaluatorKey struct{}

var getHeaderFunction = rego.Function2(
	&rego.Function{
		Name: "get_header",
		Decl: types.NewFunction(types.Args(types.S, types.A), types.S),
	},
	func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
		var headerKey string
		var headers http.Header
		if err := ast.As(a.Value, &headerKey); err != nil {
			return nil, err
		}
		if err := ast.As(b.Value, &headers); err != nil {
			return nil, err
		}
		return ast.StringTerm(headers.Get(headerKey)), nil
	},
)

func OPAMiddleware(opaModuleConfig *OPAModuleConfig, openAPISpec *OpenAPISpec, envs *EnvironmentVariables) mux.MiddlewareFunc {
	OASrouter := openAPISpec.PrepareOASRouter(openAPISpec)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.RequestURI(), "/-/") {
				next.ServeHTTP(w, r)
				return
			}

			permission, err := openAPISpec.FindPermission(OASrouter, r.URL.Path, r.Method)

			if err != nil && r.Method == http.MethodGet && r.URL.Path == envs.TargetServiceOASPath {
				evaluator := &OPAEvaluator{PermissionQuery: &TruthyEvaluator{}}
				ctx := WithOPAEvaluator(r.Context(), evaluator)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if err != nil || permission.AllowPermission == "" {
				errorMessage := "User is not allowed to request the API"
				fields := logrus.Fields{
					"originalRequestPath": r.URL.Path,
					"method":              r.Method,
					"allowPermission":     permission.AllowPermission,
				}
				if err != nil {
					fields["error"] = logrus.Fields{"message": err.Error()}
					errorMessage = "The request doesn't match any known API"
				}
				glogger.Get(r.Context()).WithFields(fields).Errorf(errorMessage)
				failResponseWithCode(w, http.StatusForbidden, errorMessage)
				return
			}

			evaluator, err := NewOPAEvaluator(permission.AllowPermission, opaModuleConfig)
			if err != nil {
				glogger.Get(r.Context()).WithError(err).Error("failed RBAC policy creation")
				failResponse(w, err.Error())
				return
			}

			ctx := WithOPAEvaluator(r.Context(), evaluator)
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
