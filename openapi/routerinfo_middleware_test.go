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

package openapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rond-authz/rond/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

var envs = config.EnvironmentVariables{}

func TestRouterInfoContext(t *testing.T) {
	nullLogger, _ := test.NewNullLogger()
	logger := logrus.NewEntry(nullLogger)

	t.Run("GetRouterInfo fails because no key has been set", func(t *testing.T) {
		ctx := context.Background()
		routerInfo, err := GetRouterInfo(ctx)
		require.EqualError(t, err, "no router info found")
		require.Empty(t, routerInfo)
	})

	t.Run("WithRouterInfo not inside mux router - empty matched path", func(t *testing.T) {
		ctx := context.Background()
		req := httptest.NewRequest("GET", "/hello", nil)
		ctx = WithRouterInfo(logger, ctx, req)
		routerInfo, err := GetRouterInfo(ctx)
		require.NoError(t, err)
		require.Equal(t, RouterInfo{
			MatchedPath:   "",
			RequestedPath: "/hello",
			Method:        "GET",
		}, routerInfo)
	})

	t.Run("WithRouterInfo without router path - matched path is empty", func(t *testing.T) {
		ctx := context.Background()
		router := mux.NewRouter()

		router.NewRoute().HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := WithRouterInfo(logger, ctx, req)

			routerInfo, err := GetRouterInfo(ctx)
			require.NoError(t, err)
			require.Equal(t, RouterInfo{
				MatchedPath:   "",
				RequestedPath: "/hello",
				Method:        "GET",
			}, routerInfo)

			w.Write([]byte("ok"))
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/hello", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, 200, w.Result().StatusCode)
	})

	t.Run("correctly get router info", func(t *testing.T) {
		ctx := context.Background()
		router := mux.NewRouter()

		router.HandleFunc("/hello/{name}", func(w http.ResponseWriter, req *http.Request) {
			ctx := WithRouterInfo(logger, ctx, req)

			routerInfo, err := GetRouterInfo(ctx)
			require.NoError(t, err)
			require.Equal(t, RouterInfo{
				MatchedPath:   "/hello/{name}",
				RequestedPath: "/hello/my-username",
				Method:        "GET",
			}, routerInfo)

			w.Write([]byte("ok"))
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/hello/my-username", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, 200, w.Result().StatusCode)
	})

	t.Run("correctly get router info with path prefix", func(t *testing.T) {
		ctx := context.Background()
		router := mux.NewRouter()

		router.PathPrefix("/hello/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := WithRouterInfo(logger, ctx, req)

			routerInfo, err := GetRouterInfo(ctx)
			require.NoError(t, err)
			require.Equal(t, RouterInfo{
				MatchedPath:   "/hello/",
				RequestedPath: "/hello/my-username",
				Method:        "GET",
			}, routerInfo)

			w.Write([]byte("ok"))
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/hello/my-username", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, 200, w.Result().StatusCode)
	})
}

func getResponseBody(t *testing.T, w *httptest.ResponseRecorder) []byte {
	t.Helper()

	responseBody, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)

	return responseBody
}
