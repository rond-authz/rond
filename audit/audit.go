// Copyright 2024 Mia srl
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

package audit

import (
	"reflect"
	"slices"

	"github.com/google/uuid"
)

const (
	AuditAdditionalDataGrantedPermissionKey = "authorization.permissions"
	AuditAdditionalDataGrantedBindingKey    = "authorization.binding"
)

var reservedLabelKeys = []string{
	AuditAdditionalDataGrantedPermissionKey,
	AuditAdditionalDataGrantedBindingKey,
}

type auditReservedFields struct {
	ID string `audit:"id"`
}

type Audit struct {
	auditReservedFields
	AggregationID string                 `audit:"aggregationId"`
	Authorization AuthzInfo              `audit:"authorization"`
	Subject       SubjectInfo            `audit:"subject"`
	RequestBody   interface{}            `audit:"requestBody"`
	Labels        map[string]interface{} `audit:"labels"`
}

type authzinfoReservedFields struct {
	GrantingPermission string `audit:"permission"`
	GrantingBindingID  string `audit:"binding"`
}

type AuthzInfo struct {
	Allowed    bool   `audit:"allowed"`
	PolicyName string `audit:"policyName"`
	authzinfoReservedFields
}

type SubjectInfo struct {
	ID     string   `audit:"id"`
	Groups []string `audit:"groups"`
}

func (a *Audit) generateID() {
	a.auditReservedFields.ID = uuid.NewString()
}

func (a *Audit) applyDataFromPolicy(data map[string]interface{}) {
	grantedBinding, ok := data[AuditAdditionalDataGrantedBindingKey]
	if ok && grantedBinding != nil {
		str, ok := grantedBinding.(string)
		if ok {
			a.Authorization.authzinfoReservedFields.GrantingBindingID = str
		}
	}

	grantedPermission, ok := data[AuditAdditionalDataGrantedPermissionKey]
	if ok && grantedPermission != nil {
		str, ok := grantedPermission.(string)
		if ok {
			a.Authorization.authzinfoReservedFields.GrantingBindingID = str
		}
	}

	if a.Labels == nil {
		a.Labels = make(map[string]interface{})
	}
	for k, v := range data {
		if slices.Contains(reservedLabelKeys, k) {
			continue
		}

		a.Labels[k] = v
	}
}

func toMap(val interface{}) map[string]interface{} {
	const tagTitle = "audit"

	var data map[string]interface{} = make(map[string]interface{})
	varType := reflect.TypeOf(val)
	if varType.Kind() != reflect.Struct {
		return nil
	}

	value := reflect.ValueOf(val)
	for i := 0; i < varType.NumField(); i++ {
		if !value.Field(i).CanInterface() {
			// Skip unexported fields
			continue
		}
		tag, ok := varType.Field(i).Tag.Lookup(tagTitle)
		var fieldName string
		if ok && len(tag) > 0 {
			fieldName = tag
		} else {
			fieldName = varType.Field(i).Name
		}
		if varType.Field(i).Type.Kind() != reflect.Struct {
			data[fieldName] = value.Field(i).Interface()
		} else {
			data[fieldName] = toMap(value.Field(i).Interface())
		}
	}

	return data
}
