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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus"
)

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

func (input *Input) buildOptimizedResourcePermissionsMap(logger *logrus.Entry, enableResourcePermissionsMapOptimization bool) {
	if !enableResourcePermissionsMapOptimization {
		return
	}
	logger.Info("preparing optimized resourcePermissionMap for OPA evaluator")
	opaPermissionsMapTime := time.Now()

	user := input.User
	permissionsOnResourceMap := make(PermissionsOnResourceMap, 0)
	rolesMap := buildRolesMap(user.Roles)
	for _, binding := range user.Bindings {
		if binding.Resource == nil {
			continue
		}

		for _, role := range binding.Roles {
			rolePermissions, ok := rolesMap[role]
			if !ok {
				continue
			}
			for _, permission := range rolePermissions {
				key := buildPermissionOnResourceKey(permission, binding.Resource.ResourceType, binding.Resource.ResourceID)
				permissionsOnResourceMap[key] = true
			}
		}
		for _, permission := range binding.Permissions {
			key := buildPermissionOnResourceKey(permission, binding.Resource.ResourceType, binding.Resource.ResourceID)
			permissionsOnResourceMap[key] = true
		}
	}
	input.User.ResourcePermissionsMap = permissionsOnResourceMap
	logger.WithField("resourcePermissionMapCreationTime", fmt.Sprintf("%+v", time.Since(opaPermissionsMapTime))).Tracef("resource permission map creation")
}

type RegoInputOptions struct {
	EnableResourcePermissionsMapOptimization bool
}

func CreateRegoQueryInput(
	logger *logrus.Entry,
	input Input,
	options RegoInputOptions,
) ([]byte, error) {
	opaInputCreationTime := time.Now()

	input.buildOptimizedResourcePermissionsMap(logger, options.EnableResourcePermissionsMapOptimization)

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed input JSON encode: %v", err)
	}
	logger.Tracef("OPA input rego creation in: %+v", time.Since(opaInputCreationTime))
	return inputBytes, nil
}

type RondInput interface {
	FromRequestInfo(user types.User, responseBody any) (Input, error)
	Context() context.Context
	OriginalRequest() *http.Request
}

type requestInfo struct {
	*http.Request
	clientTypeHeaderKey string
	pathParams          map[string]string
}

func (req requestInfo) FromRequestInfo(user types.User, responseBody any) (Input, error) {
	shouldParseJSONBody := utils.HasApplicationJSONContentType(req.Header) &&
		req.ContentLength > 0 &&
		(req.Method == http.MethodPatch || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodDelete)

	var requestBody any
	if shouldParseJSONBody {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return Input{}, fmt.Errorf("failed request body parse: %s", err.Error())
		}
		if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
			return Input{}, fmt.Errorf("failed request body deserialization: %s", err.Error())
		}
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	return Input{
		ClientType: req.Header.Get(req.clientTypeHeaderKey),
		Request: InputRequest{
			Method:     req.Method,
			Path:       req.URL.Path,
			Headers:    req.Header,
			Query:      req.URL.Query(),
			PathParams: req.pathParams,
			Body:       requestBody,
		},
		Response: InputResponse{
			Body: responseBody,
		},
		User: InputUser{
			Properties: user.Properties,
			Groups:     user.UserGroups,
			Bindings:   user.UserBindings,
			Roles:      user.UserRoles,
		},
	}, nil
}

func (r requestInfo) Context() context.Context {
	return r.Request.Context()
}

func (r requestInfo) OriginalRequest() *http.Request {
	return r.Request
}

func NewRondInput(req *http.Request, clientTypeHeaderKey string, pathParams map[string]string) RondInput {
	return requestInfo{
		Request:             req,
		clientTypeHeaderKey: clientTypeHeaderKey,
		pathParams:          pathParams,
	}
}
