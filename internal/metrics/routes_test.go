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
