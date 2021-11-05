package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
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
		return nil, fmt.Errorf("%w: unmarshal failed %s", ErrRequestFailed, err.Error())
	}
	return &oas, nil
}
