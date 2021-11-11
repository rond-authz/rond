package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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

func (oas *OpenAPISpec) getPermissionsFromRequest(req *http.Request) (XPermission, error) {
	path := req.URL.Path
	// Ensure lowercase methods since from OpenAPI 3 Specification
	// verbs are lowercase in the API Schema.
	method := strings.ToLower(req.Method)

	if _, pathOk := oas.Paths[path]; !pathOk {
		return XPermission{}, fmt.Errorf("missing oas paths")
	}

	if _, methodOk := oas.Paths[path][method]; !methodOk {
		return XPermission{}, fmt.Errorf("missing oas method")
	}
	return oas.Paths[path][method].Permission, nil
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
