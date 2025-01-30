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
	"time"

	"github.com/google/uuid"
	"github.com/rond-authz/rond/internal/utils"
)

const auditSerializerTagAnnotation = "audit"

const (
	AuditAdditionalDataGrantedPermissionKey     = "authorization.permission"
	AuditAdditionalDataGrantedBindingKey        = "authorization.binding"
	AuditAdditionalDataGrantedBindingResTypeKey = "authorization.binding.resourceType"
	AuditAdditionalDataGrantedBindingResIDKey   = "authorization.binding.resourceId"
	AuditAdditionalDataGrantedRoleKey           = "authorization.role"
	AuditAdditionalDataRequestTargetServiceKey  = "request.targetServiceName"
)

var reservedLabelKeys = []string{
	AuditAdditionalDataGrantedPermissionKey,
	AuditAdditionalDataGrantedBindingKey,
	AuditAdditionalDataGrantedRoleKey,
	AuditAdditionalDataRequestTargetServiceKey,
}

type Audit struct {
	AggregationID string
	Authorization AuthzInfo
	Subject       SubjectInfo
	Request       RequestInfo
	Labels        Labels
}

type AuthzInfo struct {
	Allowed    bool
	PolicyName string
}

type RequestInfo struct {
	Body interface{} `audit:"body,omitempty"`
	Path string      `audit:"path,omitempty"`
	Verb string      `audit:"verb,omitempty"`

	TargetServiceName string `audit:"targetServiceName,omitempty"`
	UserAgent         string `audit:"userAgent,omitempty"`
}

type SubjectInfo struct {
	ID     string   `audit:"id,omitempty"`
	Groups []string `audit:"groups,omitempty"`
}

// authzInfoToPrint defines the internal structure for an audit record and must be used by remapping
// public Audit interface.
type authzInfoToPrint struct {
	Allowed             bool   `audit:"allowed"`
	PolicyName          string `audit:"policyName"`
	Permission          string `audit:"permission,omitempty"`
	BindingID           string `audit:"binding,omitempty"`
	BindingResourceType string `audit:"bindingResourceType,omitempty"`
	BindingResourceID   string `audit:"bindingResourceId,omitempty"`
	RoleID              string `audit:"roleId,omitempty"`
}

type auditToPrint struct {
	ID            string           `audit:"id"`
	AggregationID string           `audit:"aggregationId,omitempty"`
	Authorization authzInfoToPrint `audit:"authorization"`
	Subject       SubjectInfo      `audit:"subject"`
	Request       RequestInfo      `audit:"request"`
	Labels        Labels           `audit:"labels"`
	Timestamp     int64            `audit:"timestamp"`
}

func (a *Audit) toPrint(data map[string]any) auditToPrint {
	print := auditToPrint{
		ID:            generateID(),
		AggregationID: a.AggregationID,
		Authorization: authzInfoToPrint{
			Allowed:    a.Authorization.Allowed,
			PolicyName: a.Authorization.PolicyName,
		},
		Subject:   a.Subject,
		Request:   a.Request,
		Labels:    a.Labels,
		Timestamp: time.Now().Unix(),
	}
	if data != nil {
		print.applyDataFromPolicy(data)
	}
	return print
}

func (a auditToPrint) serialize() map[string]any {
	return utils.ToMap(auditSerializerTagAnnotation, a)
}

func (a *auditToPrint) applyDataFromPolicy(data map[string]any) {
	grantedBinding, ok := data[AuditAdditionalDataGrantedBindingKey]
	if ok && grantedBinding != nil {
		str, ok := grantedBinding.(string)
		if ok {
			a.Authorization.BindingID = str
		}
	}
	grantedBindingResourceType, ok := data[AuditAdditionalDataGrantedBindingResTypeKey]
	if ok && grantedBinding != nil {
		str, ok := grantedBindingResourceType.(string)
		if ok {
			a.Authorization.BindingResourceType = str
		}
	}
	grantedBindingResourceID, ok := data[AuditAdditionalDataGrantedBindingResIDKey]
	if ok && grantedBindingResourceID != nil {
		str, ok := grantedBindingResourceID.(string)
		if ok {
			a.Authorization.BindingResourceID = str
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

	targetServiceName, ok := data[AuditAdditionalDataRequestTargetServiceKey]
	if ok && targetServiceName != nil {
		str, ok := targetServiceName.(string)
		if ok {
			a.Request.TargetServiceName = str
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
