package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestMiddleware(t *testing.T) {
	expectedMetrics := SetupMetrics("test_prefix")

	t.Run("set metrics in context", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m, err := GetFromContext(r.Context())
			require.NoError(t, err)
			require.Equal(t, expectedMetrics, m)

			w.WriteHeader(202)
		})

		handlerToTest := RequestMiddleware(expectedMetrics).Middleware(handler)

		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/path", nil)
		handlerToTest.ServeHTTP(w, req)

		require.Equal(t, http.StatusAccepted, w.Result().StatusCode)
	})
}

func TestGetFromContext(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		expectedMetrics := SetupMetrics("test_prefix")
		ctx := WithValue(context.Background(), expectedMetrics)
		m, err := GetFromContext(ctx)
		require.NoError(t, err)
		require.Equal(t, expectedMetrics, m)
	})

	t.Run("metrics not in context", func(t *testing.T) {
		m, err := GetFromContext(context.Background())
		require.EqualError(t, err, "invalid metrics in context")
		require.Empty(t, m)
	})
}
