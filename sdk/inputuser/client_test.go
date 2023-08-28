// Copyright 2023 Mia srl
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

package inputuser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/fake"

	"github.com/stretchr/testify/require"
)

func TestClientInjectorMiddleware(t *testing.T) {
	inputUserClient := &fake.InputUserClient{}

	t.Run(`context gets updated`, func(t *testing.T) {
		invoked := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			collection, err := GetClientFromContext(r.Context())
			require.NoError(t, err, "client not found")
			require.Equal(t, inputUserClient, collection)

			w.WriteHeader(http.StatusOK)
		})

		middleware := ClientInjectorMiddleware(inputUserClient)
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
		testClient := &fake.InputUserClient{}
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
