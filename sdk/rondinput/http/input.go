// Copyright 2023 Mia srl
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

package rondhttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
)

func parseRequestBody(req *http.Request) (any, error) {
	shouldParseJSONBody := utils.HasApplicationJSONContentType(req.Header) &&
		req.ContentLength > 0 &&
		(req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodDelete)

	var requestBody any
	if shouldParseJSONBody {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return core.Input{}, fmt.Errorf("failed request body parse: %s", err.Error())
		}
		if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
			return core.Input{}, fmt.Errorf("failed request body deserialization: %s", err.Error())
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return requestBody, nil
}

// TODO: before to have a stable interface, remove the usage of clientTypeHeaderKey.
// We could add to the core.Input a map[string]any to add any data passed from
// outside instead
func NewInput(req *http.Request, clientTypeHeaderKey string, pathParams map[string]string, user core.InputUser, responseBody any) (core.Input, error) {
	requestBody, err := parseRequestBody(req)
	if err != nil {
		return core.Input{}, err
	}

	return core.Input{
		ClientType: req.Header.Get(clientTypeHeaderKey),
		Request: core.InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: pathParams,
			Body:       requestBody,
		},
		Response: core.InputResponse{
			Body: responseBody,
		},
		User: user,
	}, nil
}
