package types

import (
	"context"
)

type User struct {
	UserID     string
	UserGroups []string
}

type MongoClientContextKey struct{}

type Resource struct {
	ResourceType string `bson:"resourceType" json:"resourceType"`
	ResourceID   string `bson:"resourceId" json:"resourceId"`
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
}

type RequestError struct {
	Error      string `json:"error"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}
