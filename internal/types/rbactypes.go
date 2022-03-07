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
	BindingID         string   `bson:"bindingId" json:"bindingId"`
	Groups            []string `bson:"groups" json:"groups"`
	Subjects          []string `bson:"subjects" json:"subjects"`
	Permissions       []string `bson:"permissions" json:"permissions"`
	Roles             []string `bson:"roles" json:"roles"`
	Resource          Resource `bson:"resource" json:"resource"`
	CRUDDocumentState string   `bson:"__STATE__" json:"-"`
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
	Permissions       []string `bson:"permissions" json:"permissions"`
	CRUDDocumentState string   `bson:"__STATE__" json:"-"`
}

// MongoClientContextKey is the context key that shall be used to save
// mongo Collection reference in request contexts.
type IMongoClient interface {
	Disconnect()

	RetrieveUserBindings(ctx context.Context, user *User) ([]Binding, error)
	RetrieveRoles(ctx context.Context) ([]Role, error)
	RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]Role, error)

	FindOne(ctx context.Context, collectionName string, query map[string]interface{}) (interface{}, error)
	FindMany(ctx context.Context, collectionName string, query map[string]interface{}) ([]interface{}, error)
}

type RequestError struct {
	Error      string `json:"error"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}
