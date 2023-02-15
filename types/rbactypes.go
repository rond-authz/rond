// Copyright 2021 Mia srl
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

package types

import (
	"context"
)

type User struct {
	UserID       string
	UserGroups   []string
	UserRoles    []Role
	UserBindings []Binding
}

type MongoClientContextKey struct{}

type Resource struct {
	ResourceType string `bson:"resourceType" json:"resourceType,omitempty"`
	ResourceID   string `bson:"resourceId" json:"resourceId,omitempty"`
}

type Binding struct {
	Resource          *Resource `bson:"resource" json:"resource,omitempty"`
	BindingID         string    `bson:"bindingId" json:"bindingId"`
	CRUDDocumentState string    `bson:"__STATE__" json:"-"`
	Groups            []string  `bson:"groups" json:"groups,omitempty"`
	Subjects          []string  `bson:"subjects" json:"subjects,omitempty"`
	Permissions       []string  `bson:"permissions" json:"permissions,omitempty"`
	Roles             []string  `bson:"roles" json:"roles,omitempty"`
}

type BindingFilter struct {
	BindingID string `bson:"bindingId" json:"bindingId"`
}

type BindingUpdate struct {
	Groups   []string `bson:"groups" json:"groups"`
	Subjects []string `bson:"subjects" json:"subjects"`
}

type BindingCreateResponse struct {
	ObjectID string `json:"_id"`
}

type Role struct {
	RoleID            string   `bson:"roleId" json:"roleId"`
	RoleName          string   `bson:"name" json:"name"`
	CRUDDocumentState string   `bson:"__STATE__" json:"-"`
	Permissions       []string `bson:"permissions" json:"permissions"`
}

// MongoClientContextKey is the context key that shall be used to save
// mongo Collection reference in request contexts.
type IMongoClient interface {
	Disconnect() error

	RetrieveUserBindings(ctx context.Context, user *User) ([]Binding, error)
	RetrieveRoles(ctx context.Context) ([]Role, error)
	RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]Role, error)

	FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error)
	FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error)
}

type RequestError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	StatusCode int    `json:"statusCode"`
}
