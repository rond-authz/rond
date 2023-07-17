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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rond-authz/rond/logger"
	"github.com/rond-authz/rond/types"
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

func (input *Input) buildOptimizedResourcePermissionsMap(logger logger.Logger, enableResourcePermissionsMapOptimization bool) {
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
	logger.WithField("resourcePermissionMapCreationTime", fmt.Sprintf("%+v", time.Since(opaPermissionsMapTime))).Trace("resource permission map creation")
}

type RegoInputOptions struct {
	EnableResourcePermissionsMapOptimization bool
}

func CreateRegoQueryInput(
	logger logger.Logger,
	input Input,
	options RegoInputOptions,
) ([]byte, error) {
	opaInputCreationTime := time.Now()

	input.buildOptimizedResourcePermissionsMap(logger, options.EnableResourcePermissionsMapOptimization)

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedInputEncode, err)
	}
	logger.
		WithField("inputCreationTimeMicroseconds", time.Since(opaInputCreationTime).Microseconds()).
		Trace("input creation time")
	return inputBytes, nil
}

type RondInput interface {
	Input(user types.User, responseBody any) (Input, error)
}
