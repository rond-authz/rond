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
	"slices"

	"github.com/google/uuid"
)

const (
	AuditAdditionalDataGrantedPermissionKey = "authorization.permission"
	AuditAdditionalDataGrantedBindingKey    = "authorization.binding"
	AuditAdditionalDataGrantedRoleKey       = "authorization.role"
)

var reservedLabelKeys = []string{
	AuditAdditionalDataGrantedPermissionKey,
	AuditAdditionalDataGrantedBindingKey,
	AuditAdditionalDataGrantedRoleKey,
}

type Audit struct {
	AggregationID string
	Authorization AuthzInfo
	Subject       SubjectInfo
	Request       RequestInfo
	Labels        map[string]any
}

type AuthzInfo struct {
	Allowed    bool
	PolicyName string
}

type RequestInfo struct {
	Body interface{} `audit:"body,omitempty"`
	Path string      `audit:"path,omitempty"`
	Verb string      `audit:"verb,omitempty"`
}

type SubjectInfo struct {
	ID     string   `audit:"id"`
	Groups []string `audit:"groups"`
}

// authzInfoToPrint defines the internal structure for an audit record and must be used by remapping
// public Audit interface.
type authzInfoToPrint struct {
	Allowed    bool   `audit:"allowed"`
	PolicyName string `audit:"policyName"`
	Permission string `audit:"permission"`
	BindingID  string `audit:"binding"`
	RoleID     string `audit:"roleId"`
}

type auditToPrint struct {
	ID            string           `audit:"id"`
	AggregationID string           `audit:"aggregationId"`
	Authorization authzInfoToPrint `audit:"authorization"`
	Subject       SubjectInfo      `audit:"subject"`
	Request       RequestInfo      `audit:"request"`
	Labels        map[string]any   `audit:"labels"`
}

func (a *Audit) toPrint() auditToPrint {
	return auditToPrint{
		ID:            generateID(),
		AggregationID: a.AggregationID,
		Authorization: authzInfoToPrint{
			Allowed:    a.Authorization.Allowed,
			PolicyName: a.Authorization.PolicyName,
		},
		Subject: a.Subject,
		Request: a.Request,
		Labels:  a.Labels,
	}
}

func (a *auditToPrint) applyDataFromPolicy(data map[string]any) {
	grantedBinding, ok := data[AuditAdditionalDataGrantedBindingKey]
	if ok && grantedBinding != nil {
		str, ok := grantedBinding.(string)
		if ok {
			a.Authorization.BindingID = str
		}
	}

	grantedPermission, ok := data[AuditAdditionalDataGrantedPermissionKey]
	if ok && grantedPermission != nil {
		str, ok := grantedPermission.(string)
		if ok {
			a.Authorization.Permission = str
		}
	}

	grantedRoleId, ok := data[AuditAdditionalDataGrantedRoleKey]
	if ok && grantedRoleId != nil {
		str, ok := grantedRoleId.(string)
		if ok {
			a.Authorization.RoleID = str
		}
	}

	if a.Labels == nil {
		a.Labels = make(map[string]any)
	}

	for k, v := range data {
		if slices.Contains(reservedLabelKeys, k) {
			continue
		}

		a.Labels[k] = v
	}
}

func generateID() string {
	return uuid.NewString()
}
