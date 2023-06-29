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

package rondmux

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"
)

type requestInfo struct {
	*http.Request
	clientTypeHeaderKey string
	pathParams          map[string]string
}

func (req requestInfo) Input(user types.User, responseBody any) (core.Input, error) {
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

	return core.Input{
		ClientType: req.Header.Get(req.clientTypeHeaderKey),
		Request: core.InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: req.pathParams,
			Body:       requestBody,
		},
		Response: core.InputResponse{
			Body: responseBody,
		},
		User: core.InputUser{
			Properties: user.Properties,
			Groups:     user.UserGroups,
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
		},
	}, nil
}

func NewInput(req *http.Request, clientTypeHeaderKey string, pathParams map[string]string) core.RondInput {
	return requestInfo{
		Request:             req,
		clientTypeHeaderKey: clientTypeHeaderKey,
		pathParams:          pathParams,
	}
}
