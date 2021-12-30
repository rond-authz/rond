package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/uptrace/bunrouter"
)

type XPermission struct {
	AllowPermission string `json:"allow"`
}

type VerbConfig struct {
	Permission XPermission `json:"x-permission"`
}

type PathVerbs map[string]VerbConfig

type OpenAPIPaths map[string]PathVerbs

type OpenAPISpec struct {
	Paths OpenAPIPaths `json:"paths"`
}

func cleanWildcard(path string) string {
	if strings.HasSuffix(path, "*") {
		// is a wildcard parameter that matches everything and must always be at the end of the route
		path = strings.Replace(path, "*", "*param", -1)
	}
	return path
}

func (oas *OpenAPISpec) PrepareOASRouter(openAPISpec *OpenAPISpec) *bunrouter.Router {
	OASRouter := bunrouter.New()
	for OASPath, OASContent := range openAPISpec.Paths {
		OASPath = cleanWildcard(OASPath)
		for method, methodContent := range OASContent {
			scopedMethod := method
			scopedMethodContent := methodContent
			OASRouter.Handle(strings.ToUpper(scopedMethod), OASPath, bunrouter.HTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				result, _ := json.Marshal(scopedMethodContent.Permission)
				w.Write(result)
			}))
		}
	}

	return OASRouter
}

func (oas *OpenAPISpec) FindPermission(OASRouter *bunrouter.Router, path string, method string) (XPermission, error) {
	var decoded XPermission
	recorder := httptest.NewRecorder()
	responseReader := strings.NewReader("request-permissions")
	request, _ := http.NewRequest(method, path, responseReader)
	OASRouter.ServeHTTP(recorder, request)

	buf, _ := ioutil.ReadAll(recorder.Body)
	if recorder.Code != http.StatusOK {
		return XPermission{}, fmt.Errorf("not found oas permission: %s %s", method, path)
	}

	if err := json.Unmarshal(buf, &decoded); err != nil {
		return XPermission{}, err
	}
	return decoded, nil
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

func loadOAS(log *logrus.Logger, env EnvironmentVariables) (*OpenAPISpec, error) {
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

	return nil, fmt.Errorf("missing environment variables one of %s or %s is required", TargetServiceOASPathEnvKey, APIPermissionsFilePathEnvKey)
}
