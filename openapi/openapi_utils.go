// Copyright 2021 Mia srl
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

package openapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rond-authz/rond/internal/utils"

	"github.com/sirupsen/logrus"
	"github.com/uptrace/bunrouter"
)

const HTTPScheme = "http"

var AllHTTPMethod = "all"

var OasSupportedHTTPMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodHead,
}
var (
	ErrRequestFailed = errors.New("request failed")
)

var ErrNotFoundOASDefinition = errors.New("not found oas definition")

type XPermissionKey struct{}

type PermissionOptions struct {
	EnableResourcePermissionsMapOptimization bool `json:"enableResourcePermissionsMapOptimization"`
}

// Config v1 //
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

type XPermission struct {
	AllowPermission string                      `json:"allow"`
	ResponseFilter  ResponseFilterConfiguration `json:"responseFilter"`
	ResourceFilter  ResourceFilter              `json:"resourceFilter"`
	Options         PermissionOptions           `json:"options"`
}

// END Config v1 //

// Config v2 //
type QueryOptions struct {
	HeaderName string `json:"headerName"`
}

type RequestFlow struct {
	PolicyName    string       `json:"policyName"`
	GenerateQuery bool         `json:"generateQuery"`
	QueryOptions  QueryOptions `json:"queryOptions"`
}

type ResponseFlow struct {
	PolicyName string `json:"policyName"`
}

type RondConfig struct {
	RequestFlow  RequestFlow       `json:"requestFlow"`
	ResponseFlow ResponseFlow      `json:"responseFlow"`
	Options      PermissionOptions `json:"options"`
}

// END Config v2 //

type VerbConfig struct {
	PermissionV1 *XPermission `json:"x-permission"`
	PermissionV2 *RondConfig  `json:"x-rond"`
}

type PathVerbs map[string]VerbConfig

type OpenAPIPaths map[string]PathVerbs

type OpenAPISpec struct {
	Paths OpenAPIPaths `json:"paths"`
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

func createOasHandler(scopedMethodContent VerbConfig) func(http.ResponseWriter, *http.Request) {
	permission := scopedMethodContent.PermissionV2
	return func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("allow", permission.RequestFlow.PolicyName)
		header.Set("resourceFilter.rowFilter.enabled", strconv.FormatBool(permission.RequestFlow.GenerateQuery))
		header.Set("resourceFilter.rowFilter.headerKey", permission.RequestFlow.QueryOptions.HeaderName)
		header.Set("responseFilter.policy", permission.ResponseFlow.PolicyName)
		header.Set("options.enableResourcePermissionsMapOptimization", strconv.FormatBool(permission.Options.EnableResourcePermissionsMapOptimization))
	}
}

func (oas *OpenAPISpec) PrepareOASRouter() *bunrouter.CompatRouter {
	OASRouter := bunrouter.New().Compat()
	routeMap := oas.createRoutesMap()
	for OASPath, OASContent := range oas.Paths {

		OASPathCleaned := ConvertPathVariablesToColons(cleanWildcard(OASPath))
		for method, methodContent := range OASContent {
			scopedMethod := strings.ToUpper(method)

			handler := createOasHandler(methodContent)

			if scopedMethod != strings.ToUpper(AllHTTPMethod) {
				OASRouter.Handle(scopedMethod, OASPathCleaned, handler)
				continue
			}

			for _, method := range OasSupportedHTTPMethods {
				if !routeMap.contains(OASPath, method) {
					OASRouter.Handle(method, OASPathCleaned, handler)
				}
			}
		}
	}

	return OASRouter
}

// FIXME: This is not a logic method of OAS, but could be a method of OASRouter
func (oas *OpenAPISpec) FindPermission(OASRouter *bunrouter.CompatRouter, path string, method string) (RondConfig, error) {
	recorder := httptest.NewRecorder()
	responseReader := strings.NewReader("request-permissions")
	request, _ := http.NewRequest(method, path, responseReader)
	OASRouter.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		return RondConfig{}, fmt.Errorf("%w: %s %s", ErrNotFoundOASDefinition, utils.SanitizeString(method), utils.SanitizeString(path))
	}

	recorderResult := recorder.Result()
	rowFilterEnabled, err := strconv.ParseBool(recorderResult.Header.Get("resourceFilter.rowFilter.enabled"))
	if err != nil {
		return RondConfig{}, fmt.Errorf("error while parsing rowFilter.enabled: %s", err)
	}
	enableResourcePermissionsMapOptimization, err := strconv.ParseBool(recorderResult.Header.Get("options.enableResourcePermissionsMapOptimization"))
	if err != nil {
		return RondConfig{}, fmt.Errorf("error while parsing rowFilter.enabled: %s", err)
	}
	return RondConfig{
		RequestFlow: RequestFlow{
			PolicyName:    recorderResult.Header.Get("allow"),
			GenerateQuery: rowFilterEnabled,
			QueryOptions: QueryOptions{
				HeaderName: recorderResult.Header.Get("resourceFilter.rowFilter.headerKey"),
			},
		},
		ResponseFlow: ResponseFlow{
			PolicyName: recorderResult.Header.Get("responseFilter.policy"),
		},
		Options: PermissionOptions{
			EnableResourcePermissionsMapOptimization: enableResourcePermissionsMapOptimization,
		},
	}, nil
}

func newRondConfigFromPermissionV1(v1Permission *XPermission) *RondConfig {
	return &RondConfig{
		RequestFlow: RequestFlow{
			PolicyName:    v1Permission.AllowPermission,
			GenerateQuery: v1Permission.ResourceFilter.RowFilter.Enabled,
			QueryOptions: QueryOptions{
				HeaderName: v1Permission.ResourceFilter.RowFilter.HeaderKey,
			},
		},
		ResponseFlow: ResponseFlow{
			PolicyName: v1Permission.ResponseFilter.Policy,
		},
	}
}

// adaptOASSpec transforms input OpenAPISpec transforming x-permission based configuration
// to the x-rond based one.
// If a configurations presents both x-permission and x-rond for a specific verb the
// provided x-rond will be considered as the adapter will skip the verb.
func adaptOASSpec(spec *OpenAPISpec) {
	for path := range spec.Paths {
		pathConfig := spec.Paths[path]
		for verb := range pathConfig {
			verbConfig := pathConfig[verb]
			if verbConfig.PermissionV1 != nil {
				if verbConfig.PermissionV2 == nil {
					verbConfig.PermissionV2 = newRondConfigFromPermissionV1(verbConfig.PermissionV1)
				}
				verbConfig.PermissionV1 = nil
			}
			pathConfig[verb] = verbConfig
		}
		spec.Paths[path] = pathConfig
	}
}

func deserializeSpec(spec []byte, errorWrapper error) (*OpenAPISpec, error) {
	var oas OpenAPISpec
	if err := json.Unmarshal(spec, &oas); err != nil {
		return nil, fmt.Errorf("%w: unmarshal error: %s", errorWrapper, err.Error())
	}

	adaptOASSpec(&oas)

	return &oas, nil
}

func fetchOpenAPI(log *logrus.Logger, url string) (*OpenAPISpec, error) {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRequestFailed, err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.WithField("error", logrus.Fields{"message": err.Error()}).Error("failed response body close")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: invalid status code %d", ErrRequestFailed, resp.StatusCode)
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	return deserializeSpec(bodyBytes, ErrRequestFailed)
}

func LoadOASFile(APIPermissionsFilePath string) (*OpenAPISpec, error) {
	fileContentByte, err := utils.ReadFile(APIPermissionsFilePath)
	if err != nil {
		return nil, err
	}
	return deserializeSpec(fileContentByte, utils.ErrFileLoadFailed)
}

type LoadOptions struct {
	APIPermissionsFilePath string
	TargetServiceOASPath   string
	TargetServiceHost      string
}

func LoadOASFromFileOrNetwork(log *logrus.Logger, config LoadOptions) (*OpenAPISpec, error) {
	if config.APIPermissionsFilePath != "" {
		log.WithField("oasFilePath", config.APIPermissionsFilePath).Debug("Attempt to load OAS from file")
		oas, err := LoadOASFile(config.APIPermissionsFilePath)
		if err != nil {
			log.WithFields(logrus.Fields{
				"APIPermissionsFilePath": config.APIPermissionsFilePath,
			}).Warn("failed api permissions file read")
			return nil, err
		}

		return oas, nil
	}

	if config.TargetServiceOASPath != "" {
		log.WithField("oasApiPath", config.TargetServiceOASPath).Debug("Attempt to load OAS from target service")
		var oas *OpenAPISpec
		documentationURL := fmt.Sprintf("%s://%s%s", HTTPScheme, config.TargetServiceHost, config.TargetServiceOASPath)
		for {
			fetchedOAS, err := fetchOpenAPI(log, documentationURL)
			if err != nil {
				log.WithFields(logrus.Fields{
					"targetServiceHost": config.TargetServiceHost,
					"targetOASPath":     config.TargetServiceOASPath,
					"error":             logrus.Fields{"message": err.Error()},
				}).Warn("failed OAS fetch, retry in 1s")
				time.Sleep(1 * time.Second)
				continue
			}
			oas = fetchedOAS
			break
		}
		return oas, nil
	}

	return nil, fmt.Errorf("missing openapi config: one of TargetServiceOASPath or APIPermissionsFilePath is required")
}

func WithXPermission(requestContext context.Context, permission *RondConfig) context.Context {
	return context.WithValue(requestContext, XPermissionKey{}, permission)
}

// GetXPermission can be used by a request handler to get XPermission instance from its context.
func GetXPermission(requestContext context.Context) (*RondConfig, error) {
	permission, ok := requestContext.Value(XPermissionKey{}).(*RondConfig)
	if !ok {
		return nil, fmt.Errorf("no permission configuration found in request context")
	}

	return permission, nil
}

var matchColons = regexp.MustCompile(`\/:(\w+)`)

func ConvertPathVariablesToBrackets(path string) string {
	return matchColons.ReplaceAllString(path, "/{$1}")
}

var matchBrackets = regexp.MustCompile(`\/{(\w+)}`)

func ConvertPathVariablesToColons(path string) string {
	return matchBrackets.ReplaceAllString(path, "/:$1")
}
