package core

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"
)

//	type RondCore struct {
//		partialEvaluators
//	}
type OPAModuleConfigKey struct{}

type OPAModuleConfig struct {
	Name    string
	Content string
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

type Input struct {
	Request    InputRequest  `json:"request"`
	Response   InputResponse `json:"response"`
	ClientType string        `json:"clientType,omitempty"`
	User       InputUser     `json:"user"`
}
type InputRequest struct {
	Body       interface{}       `json:"body,omitempty"`
	Headers    http.Header       `json:"headers,omitempty"`
	Query      url.Values        `json:"query,omitempty"`
	PathParams map[string]string `json:"pathParams,omitempty"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
}

type InputResponse struct {
	Body interface{} `json:"body,omitempty"`
}

type InputUser struct {
	Properties             map[string]interface{}   `json:"properties,omitempty"`
	Groups                 []string                 `json:"groups,omitempty"`
	Bindings               []types.Binding          `json:"bindings,omitempty"`
	Roles                  []types.Role             `json:"roles,omitempty"`
	ResourcePermissionsMap PermissionsOnResourceMap `json:"resourcePermissionsMap,omitempty"`
}

type PermissionOnResourceKey string

type PermissionsOnResourceMap map[PermissionOnResourceKey]bool

func buildPermissionOnResourceKey(permission string, resourceType string, resourceId string) PermissionOnResourceKey {
	return PermissionOnResourceKey(fmt.Sprintf("%s:%s:%s", permission, resourceType, resourceId))
}

func LoadRegoModule(rootDirectory string) (*OPAModuleConfig, error) {
	var regoModulePath string
	//#nosec G104 -- Produces a false positive
	filepath.Walk(rootDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
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
	fileContent, err := utils.ReadFile(regoModulePath)
	if err != nil {
		return nil, fmt.Errorf("failed rego file read: %s", err.Error())
	}

	return &OPAModuleConfig{
		Name:    filepath.Base(regoModulePath),
		Content: string(fileContent),
	}, nil
}
