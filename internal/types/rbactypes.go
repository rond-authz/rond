package types

import (
	"context"
)

type User struct {
	UserID     string
	UserGroups []string
}

type MongoClientContextKey struct{}

type Binding struct {
	BindingID         string   `bson:"bindingId"`
	Groups            []string `bson:"groups"`
	Subjects          []string `bson:"subjects"`
	Permissions       []string `bson:"permissions"`
	Roles             []string `bson:"roles"`
	CRUDDocumentState string   `bson:"__STATE__"`
}

type Role struct {
	RoleID            string   `bson:"roleId"`
	Permissions       []string `bson:"permissions"`
	CRUDDocumentState string   `bson:"__STATE__"`
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
