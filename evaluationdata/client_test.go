package evaluationdata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/types"
	"github.com/stretchr/testify/require"
)

func TestClientInjectorMiddleware(t *testing.T) {
	testCollections := &FakeClient{}

	t.Run(`context gets updated`, func(t *testing.T) {
		invoked := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			collection, err := GetClientFromContext(r.Context())
			require.NoError(t, err, "client not found")
			require.Equal(t, testCollections, collection)

			w.WriteHeader(http.StatusOK)
		})

		middleware := ClientInjectorMiddleware(testCollections)
		builtMiddleware := middleware(next)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)

		builtMiddleware.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Result().StatusCode, "Unexpected status code")
		require.True(t, invoked, "Next middleware not invoked")
	})
}

func TestGetClientFromContext(t *testing.T) {
	t.Run(`config not found in context`, func(t *testing.T) {
		ctx := context.Background()
		config, err := GetClientFromContext(ctx)
		require.True(t, config == nil)
		require.NoError(t, err, "no error expected")
	})

	t.Run(`config found in context`, func(t *testing.T) {
		testClient := &FakeClient{}
		ctx := WithClient(context.Background(), testClient)
		foundConfig, err := GetClientFromContext(ctx)
		require.NoError(t, err, "unexpected error")
		require.True(t, foundConfig != nil)
	})

	t.Run(`client not found in context`, func(t *testing.T) {
		ctx := context.WithValue(context.Background(), clientContextKey{}, "")
		foundConfig, err := GetClientFromContext(ctx)
		require.EqualError(t, err, "no client found in context")
		require.Nil(t, foundConfig)
	})
}

type FakeClient struct{}

func (f FakeClient) RetrieveUserBindings(ctx context.Context, user *types.User) ([]types.Binding, error) {
	return []types.Binding{}, nil
}
func (f FakeClient) RetrieveRoles(ctx context.Context) ([]types.Role, error) {
	return []types.Role{}, nil
}
func (f FakeClient) RetrieveUserRolesByRolesID(ctx context.Context, userRolesId []string) ([]types.Role, error) {
	return []types.Role{}, nil
}
func (f FakeClient) Disconnect() error {
	return nil
}
