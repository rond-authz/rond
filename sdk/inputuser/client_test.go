package inputuser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/mocks"
	"github.com/stretchr/testify/require"
)

func TestClientInjectorMiddleware(t *testing.T) {
	testCollections := &mocks.MongoClientMock{}

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
		testClient := &mocks.MongoClientMock{}
		ctx := AddClientInContext(context.Background(), testClient)
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
