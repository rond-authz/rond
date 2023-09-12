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

package helpers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetHeadersToProxy(t *testing.T) {
	t.Run("not set header if empty headers to proxy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		actual := GetHeadersToProxy(req, nil)

		expected := http.Header{}

		require.Equal(t, actual, expected)
	})

	t.Run("get headers to proxy correctly", func(t *testing.T) {
		requestHeaders := http.Header{}
		requestHeaders.Set("foo", "bar")
		requestHeaders.Set("taz", "ok")
		requestHeaders.Set("proxy", "me")

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header = requestHeaders

		actual := GetHeadersToProxy(req, []string{"foo", "proxy"})

		expected := http.Header{}
		expected.Set("foo", "bar")
		expected.Set("proxy", "me")

		require.Equal(t, actual, expected)
	})
}
