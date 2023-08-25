package inputuser

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rond-authz/rond/types"

	"github.com/gorilla/mux"
)

// Client allows to retrieve information to evaluate policy, as bindings and roles
type Client interface {
	Disconnect() error

	RetrieveUserBindings(ctx context.Context, user types.User) ([]types.Binding, error)
	RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error)
}

type clientContextKey struct{}

// ClientInjectorMiddleware will inject into request context the
// mongo collections.
func ClientInjectorMiddleware(client Client) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := AddClientInContext(r.Context(), client)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AddClientInContext(ctx context.Context, mongoClient Client) context.Context {
	return context.WithValue(ctx, clientContextKey{}, mongoClient)
}

// GetClientFromContext extracts mongo collections adapter struct from
// provided context.
func GetClientFromContext(ctx context.Context) (Client, error) {
	clientInterface := ctx.Value(clientContextKey{})
	if clientInterface == nil {
		return nil, nil
	}

	client, ok := clientInterface.(Client)
	if !ok {
		return nil, fmt.Errorf("no client found in context")
	}
	return client, nil
}
