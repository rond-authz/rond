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

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/utils"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/sirupsen/logrus"
)

var (
	ErrRequestFailed  = errors.New("request failed")
	ErrFileLoadFailed = errors.New("file loading failed")
)

type OPAModuleConfigKey struct{}

type OPAModuleConfig struct {
	Name    string
	Content string
}

func OPAMiddleware(opaModuleConfig *OPAModuleConfig, openAPISpec *OpenAPISpec, envs *config.EnvironmentVariables, policyEvaluators PartialResultsEvaluators) mux.MiddlewareFunc {
	OASrouter := openAPISpec.PrepareOASRouter()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if utils.Contains(statusRoutes, r.URL.RequestURI()) {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.EscapedPath()
			if envs.Standalone {
				path = strings.Replace(r.URL.EscapedPath(), envs.PathPrefixStandalone, "", 1)
			}

			permission, err := openAPISpec.FindPermission(OASrouter, path, r.Method)
			if r.Method == http.MethodGet && r.URL.Path == envs.TargetServiceOASPath && permission.AllowPermission == "" {
				glogger.Get(r.Context()).WithError(err).Info("Proxying call to OAS Path even with no permission")
				next.ServeHTTP(w, r)
				return
			}

			if err != nil || permission.AllowPermission == "" {
				errorMessage := "User is not allowed to request the API"
				fields := logrus.Fields{
					"originalRequestPath": r.URL.Path,
					"method":              r.Method,
					"allowPermission":     permission.AllowPermission,
				}
				technicalError := ""
				if err != nil {
					technicalError = err.Error()
					fields["error"] = logrus.Fields{"message": err.Error()}
					errorMessage = "The request doesn't match any known API"
				}
				glogger.Get(r.Context()).WithFields(fields).Errorf(errorMessage)
				failResponseWithCode(w, http.StatusForbidden, technicalError, errorMessage)
				return
			}

			ctx := WithXPermission(
				WithOPAModuleConfig(
					WithPartialResultsEvaluators(
						r.Context(),
						policyEvaluators,
					),
					opaModuleConfig,
				),
				&permission,
			)
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

func WithOPAModuleConfig(requestContext context.Context, permission *OPAModuleConfig) context.Context {
	return context.WithValue(requestContext, OPAModuleConfigKey{}, permission)
}

// GetOPAModuleConfig can be used by a request handler to get OPAModuleConfig instance from its context.
func GetOPAModuleConfig(requestContext context.Context) (*OPAModuleConfig, error) {
	permission, ok := requestContext.Value(OPAModuleConfigKey{}).(*OPAModuleConfig)
	if !ok {
		return nil, fmt.Errorf("no opa module config found in request context")
	}

	return permission, nil
}
