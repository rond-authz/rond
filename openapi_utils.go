package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

// TODO: Expected example of OAS
// {
// 	"paths": {
// 		"/": {
// 			"get": {
// 				"x-permission" : {
// 					"allow": "foo.bar"
// 				}
// 			}
// 		}
// 	}
// }

// TODO: Is this a good struct?
type XPermission struct {
	AllowPermission string `json:"allow"`
}

// TODO: Is this a good struct?
type VerbConfig struct {
	Permission XPermission `json:"x-permission"`
}

type PathVerbs map[string]VerbConfig

type OpenAPIPaths map[string]PathVerbs

type OpenAPISpec struct {
	Paths OpenAPIPaths `json:"paths"`
}

var (
	ErrRequestFailed = errors.New("request failed")
)

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
