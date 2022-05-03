package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/types"

	"github.com/sirupsen/logrus"
	"github.com/uptrace/bunrouter"
)

const ALL_METHODS = "ALL"

type XPermissionKey struct{}

type PermissionOptions struct {
	EnableResourcePermissionsMapOptimization bool `json:"enableResourcePermissionsMapOptimization"`
}
type XPermission struct {
	AllowPermission string                      `json:"allow"`
	ResponseFilter  ResponseFilterConfiguration `json:"responseFilter"`
	ResourceFilter  ResourceFilter              `json:"resourceFilter"`
	Options         PermissionOptions           `json:"options"`
}

type ResourceFilter struct {
	RowFilter RowFilterConfiguration `json:"rowFilter"`
}

type RowFilterConfiguration struct {
	HeaderKey string `json:"headerKey"`
	Enabled   bool   `json:"enabled"`
}

type ResponseFilterConfiguration struct {
	Policy string `json:"policy"`
}

type VerbConfig struct {
	Permission XPermission `json:"x-permission"`
}

type PathVerbs map[string]VerbConfig

type OpenAPIPaths map[string]PathVerbs

type OpenAPISpec struct {
	Paths OpenAPIPaths `json:"paths"`
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

type PermissionOnResourceKey string

type PermissionsOnResourceMap map[PermissionOnResourceKey]bool

func buildPermissionOnResourceKey(permission string, resourceType string, resourceId string) PermissionOnResourceKey {
	return PermissionOnResourceKey(fmt.Sprintf("%s:%s:%s", permission, resourceType, resourceId))
}

type InputUser struct {
	Properties             map[string]interface{}   `json:"properties,omitempty"`
	Groups                 []string                 `json:"groups,omitempty"`
	Bindings               []types.Binding          `json:"bindings,omitempty"`
	Roles                  []types.Role             `json:"roles,omitempty"`
	ResourcePermissionsMap PermissionsOnResourceMap `json:"resourcePermissionsMap,omitempty"`
}

func cleanWildcard(path string) string {
	if strings.HasSuffix(path, "*") {
		// is a wildcard parameter that matches everything and must always be at the end of the route
		path = strings.ReplaceAll(path, "*", "*param")
	}
	return path
}

type RoutesMap map[string]bool

func (oas *OpenAPISpec) createRoutesMap() RoutesMap {
	routesMap := make(RoutesMap)
	for OASPath, OASContent := range oas.Paths {
		for method := range OASContent {
			route := OASPath + "/" + strings.ToUpper(method)
			routesMap[route] = true
		}
	}
	return routesMap
}

func (rMap RoutesMap) contains(path string, method string) bool {
	route := path + "/" + method
	_, hasRoute := rMap[route]
	return hasRoute
}

func (oas *OpenAPISpec) PrepareOASRouter() *bunrouter.CompatRouter {
	OASRouter := bunrouter.New().Compat()
	routeMap := oas.createRoutesMap()
	for OASPath, OASContent := range oas.Paths {

		OASPathCleaned := convertPathVariablesToColons(cleanWildcard(OASPath))
		for method, methodContent := range OASContent {
			scopedMethod := strings.ToUpper(method)
			scopedMethodContent := methodContent

			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("allow", scopedMethodContent.Permission.AllowPermission)
				w.Header().Set("resourceFilter.rowFilter.enabled", strconv.FormatBool(scopedMethodContent.Permission.ResourceFilter.RowFilter.Enabled))
				w.Header().Set("resourceFilter.rowFilter.headerKey", scopedMethodContent.Permission.ResourceFilter.RowFilter.HeaderKey)
				w.Header().Set("responseFilter.policy", scopedMethodContent.Permission.ResponseFilter.Policy)
				w.Header().Set("options.enableResourcePermissionsMapOptimization", strconv.FormatBool(scopedMethodContent.Permission.Options.EnableResourcePermissionsMapOptimization))
			}

			if scopedMethod != ALL_METHODS {
				OASRouter.Handle(scopedMethod, OASPathCleaned, handler)
				continue
			}

			if !routeMap.contains(OASPath, http.MethodGet) {
				OASRouter.GET(OASPathCleaned, handler)
			}
			if !routeMap.contains(OASPath, http.MethodPost) {
				OASRouter.POST(OASPathCleaned, handler)
			}
			if !routeMap.contains(OASPath, http.MethodPut) {
				OASRouter.PUT(OASPathCleaned, handler)
			}
			if !routeMap.contains(OASPath, http.MethodPatch) {
				OASRouter.PATCH(OASPathCleaned, handler)
			}
			if !routeMap.contains(OASPath, http.MethodDelete) {
				OASRouter.DELETE(OASPathCleaned, handler)
			}
		}
	}

	return OASRouter
}

// FIXME: This is not a logic method of OAS, but could be a method of OASRouter
func (oas *OpenAPISpec) FindPermission(OASRouter *bunrouter.CompatRouter, path string, method string) (XPermission, error) {
	recorder := httptest.NewRecorder()
	responseReader := strings.NewReader("request-permissions")
	request, _ := http.NewRequest(method, path, responseReader)
	OASRouter.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		return XPermission{}, fmt.Errorf("not found oas permission: %s %s", method, path)
	}

	recorderResult := recorder.Result()
	rowFilterEnabled, err := strconv.ParseBool(recorderResult.Header.Get("resourceFilter.rowFilter.enabled"))
	if err != nil {
		return XPermission{}, fmt.Errorf("error while parsing rowFilter.enabled: %s", err)
	}
	enableResourcePermissionsMapOptimization, err := strconv.ParseBool(recorderResult.Header.Get("options.enableResourcePermissionsMapOptimization"))
	if err != nil {
		return XPermission{}, fmt.Errorf("error while parsing rowFilter.enabled: %s", err)
	}
	return XPermission{
		AllowPermission: recorderResult.Header.Get("allow"),
		ResponseFilter:  ResponseFilterConfiguration{Policy: recorderResult.Header.Get("responseFilter.policy")},
		ResourceFilter: ResourceFilter{
			RowFilter: RowFilterConfiguration{Enabled: rowFilterEnabled, HeaderKey: recorderResult.Header.Get("resourceFilter.rowFilter.headerKey")},
		},
		Options: PermissionOptions{
			EnableResourcePermissionsMapOptimization: enableResourcePermissionsMapOptimization,
		},
	}, nil
}

func fetchOpenAPI(url string) (*OpenAPISpec, error) {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: invalid status code %d", ErrRequestFailed, resp.StatusCode)
	}

	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	var oas OpenAPISpec
	if err := json.Unmarshal(bodyBytes, &oas); err != nil {
		return nil, fmt.Errorf("%w: unmarshal error: %s", ErrRequestFailed, err.Error())
	}
	return &oas, nil
}

func loadOASFile(APIPermissionsFilePath string) (*OpenAPISpec, error) {
	fileContentByte, err := ioutil.ReadFile(APIPermissionsFilePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileLoadFailed, err.Error())
	}

	var oas OpenAPISpec
	if err := json.Unmarshal(fileContentByte, &oas); err != nil {
		return nil, fmt.Errorf("%w: unmarshal error: %s", ErrFileLoadFailed, err.Error())
	}

	return &oas, nil
}

func loadOAS(log *logrus.Logger, env config.EnvironmentVariables) (*OpenAPISpec, error) {
	if env.APIPermissionsFilePath != "" {
		oas, err := loadOASFile(env.APIPermissionsFilePath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"APIPermissionsFilePath": env.APIPermissionsFilePath,
			}).Warn("failed api permissions file read")
			return nil, err
		}

		return oas, nil
	}

	if env.TargetServiceOASPath != "" {
		var oas *OpenAPISpec
		documentationURL := fmt.Sprintf("%s://%s%s", HTTPScheme, env.TargetServiceHost, env.TargetServiceOASPath)
		for {
			fetchedOAS, err := fetchOpenAPI(documentationURL)
			if err != nil {
				log.WithFields(logrus.Fields{
					"targetServiceHost": env.TargetServiceHost,
					"targetOASPath":     env.TargetServiceOASPath,
					"error": logrus.Fields{
						"message": err.Error(),
					},
				}).Warn("failed OAS fetch")
				time.Sleep(1 * time.Second)
				continue
			}
			oas = fetchedOAS
			break
		}
		return oas, nil
	}

	return nil, fmt.Errorf("missing environment variables one of %s or %s is required", config.TargetServiceOASPathEnvKey, config.APIPermissionsFilePathEnvKey)
}

func WithXPermission(requestContext context.Context, permission *XPermission) context.Context {
	return context.WithValue(requestContext, XPermissionKey{}, permission)
}

// GetXPermission can be used by a request handler to get XPermission instance from its context.
func GetXPermission(requestContext context.Context) (*XPermission, error) {
	permission, ok := requestContext.Value(XPermissionKey{}).(*XPermission)
	if !ok {
		return nil, fmt.Errorf("no permission configuration found in request context")
	}

	return permission, nil
}
