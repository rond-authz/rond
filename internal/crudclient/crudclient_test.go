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

package crudclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/rond-authz/rond/helpers"
	"github.com/stretchr/testify/require"
)

func TestCRUDClient(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name"

	t.Run("New", func(t *testing.T) {
		t.Run("should return a Client instance", func(t *testing.T) {
			crudClient, err := New(usersCrudBaseURL)
			require.NoError(t, err)
			require.NotNil(t, crudClient)
		})

		t.Run("https is allowed", func(t *testing.T) {
			crudClient, err := New("https://crud.example.org")
			require.NoError(t, err)
			require.NotNil(t, crudClient)
		})

		t.Run("should return error invalid url", func(t *testing.T) {
			crudClient, err := New("in\t")
			require.Error(t, err)
			require.Nil(t, crudClient)
		})

		t.Run("should return error on unknown protocol", func(t *testing.T) {
			crudClient, err := New("in://validURL")
			require.Error(t, err)
			require.Nil(t, crudClient)
		})

		t.Run("should return error if URL is not absolute - 1", func(t *testing.T) {
			crudClient, err := New("validURL")
			require.Error(t, err)
			require.Nil(t, crudClient)
		})

		t.Run("should return error if URL is not absolute - 2", func(t *testing.T) {
			crudClient, err := New("/validURL")
			require.Error(t, err)
			require.Nil(t, crudClient)
		})
	})
}

func TestGet(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name/"

	crudClient, err := New(usersCrudBaseURL)
	require.NoError(t, err)
	require.NotNil(t, crudClient)
	var ctx = context.Background()

	type ResponseBody struct {
		Bar string `json:"bar"`
	}

	t.Run("returns error creating request", func(t *testing.T) {
		err := crudClient.Get(ctx, "	", nil)
		require.Error(t, err)
	})

	t.Run("returns error if context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		err := crudClient.Get(ctx, "", nil)
		require.EqualError(t, err, context.DeadlineExceeded.Error())
	})

	t.Run("returns error if crud returns 404", func(t *testing.T) {
		MockGet(t, usersCrudBaseURL, 404, nil, nil)

		err := crudClient.Get(ctx, "", nil)
		require.EqualError(t, err, "GET http://crud.example.org/my-coll-name/?: 404 - null\n")
	})

	t.Run("correctly returns if crud returns 200", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		MockGet(t, usersCrudBaseURL, 200, expectedResponseBody, nil)

		var responseBody ResponseBody
		err := crudClient.Get(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})

	t.Run("correctly returns if crud returns 200 with additional headers to proxy", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		headersToProxy := http.Header{}
		headersToProxy.Set("request-id", "123")
		headersToProxy.Set("taz", "ok")

		ctx = helpers.AddHeadersToProxyToContext(ctx, headersToProxy)

		MockGet(t, usersCrudBaseURL, 200, expectedResponseBody, headersToProxy)

		var responseBody ResponseBody
		err := crudClient.Get(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})
}

func TestPost(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name/"

	crudClient, err := New(usersCrudBaseURL)
	require.NoError(t, err)
	require.NotNil(t, crudClient)
	var ctx = context.Background()

	type ResponseBody struct {
		Bar string `json:"bar"`
	}

	t.Run("returns error creating request", func(t *testing.T) {
		err := crudClient.Post(ctx, nil, nil)
		require.Error(t, err)
	})

	t.Run("returns error if context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		err := crudClient.Post(ctx, "", nil)
		require.EqualError(t, err, context.DeadlineExceeded.Error())
	})

	t.Run("returns error if crud returns 404", func(t *testing.T) {
		MockPost(t, usersCrudBaseURL, 404, nil, nil)

		err := crudClient.Post(ctx, "", nil)
		require.EqualError(t, err, "POST http://crud.example.org/my-coll-name/: 404 - null\n")
	})

	t.Run("correctly returns if crud returns 200", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		MockPost(t, usersCrudBaseURL, 200, expectedResponseBody, nil)

		var responseBody ResponseBody
		err := crudClient.Get(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})

	t.Run("correctly returns if crud returns 200 with additional headers to proxy", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		headersToProxy := http.Header{}
		headersToProxy.Set("request-id", "123")
		headersToProxy.Set("taz", "ok")

		ctx = helpers.AddHeadersToProxyToContext(ctx, headersToProxy)

		MockPost(t, usersCrudBaseURL, 200, expectedResponseBody, headersToProxy)

		var responseBody ResponseBody
		err := crudClient.Get(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})
}

func TestDelete(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name/"

	crudClient, err := New(usersCrudBaseURL)
	require.NoError(t, err)
	require.NotNil(t, crudClient)
	var ctx = context.Background()

	type ResponseBody struct {
		Bar string `json:"bar"`
	}

	t.Run("returns error creating request", func(t *testing.T) {
		err := crudClient.Delete(ctx, "", nil)
		require.Error(t, err)
	})

	t.Run("returns error if context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		err := crudClient.Delete(ctx, "", nil)
		require.EqualError(t, err, context.DeadlineExceeded.Error())
	})

	t.Run("returns error if crud returns 404", func(t *testing.T) {
		MockDelete(t, usersCrudBaseURL, 404, nil, nil)

		err := crudClient.Delete(ctx, "", nil)
		require.EqualError(t, err, "DELETE http://crud.example.org/my-coll-name/?: 404 - null\n")
	})

	t.Run("correctly returns if crud returns 200", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		MockDelete(t, usersCrudBaseURL, 200, expectedResponseBody, nil)

		var responseBody ResponseBody
		err := crudClient.Delete(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})

	t.Run("correctly returns if crud returns 200 with additional headers to proxy", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		headersToProxy := http.Header{}
		headersToProxy.Set("request-id", "123")
		headersToProxy.Set("taz", "ok")

		ctx = helpers.AddHeadersToProxyToContext(ctx, headersToProxy)

		MockDelete(t, usersCrudBaseURL, 200, expectedResponseBody, headersToProxy)

		var responseBody ResponseBody
		err := crudClient.Delete(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})
}

func TestPatchBulk(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name/"

	crudClient, err := New(usersCrudBaseURL)
	require.NoError(t, err)
	require.NotNil(t, crudClient)
	var ctx = context.Background()

	type ResponseBody struct {
		Bar string `json:"bar"`
	}

	t.Run("returns error creating request", func(t *testing.T) {
		err := crudClient.PatchBulk(ctx, nil, nil)
		require.Error(t, err)
	})

	t.Run("returns error if context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(ctx, 0)
		defer cancel()

		err := crudClient.PatchBulk(ctx, "", nil)
		require.EqualError(t, err, context.DeadlineExceeded.Error())
	})

	t.Run("returns error if crud returns 404", func(t *testing.T) {
		MockPatchBulk(t, usersCrudBaseURL, 404, nil, nil)

		err := crudClient.PatchBulk(ctx, "", nil)
		require.EqualError(t, err, "PATCH http://crud.example.org/my-coll-name/: 404 - null\n")
	})

	t.Run("correctly returns if crud returns 200", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		MockPatchBulk(t, usersCrudBaseURL, 200, expectedResponseBody, nil)

		var responseBody ResponseBody
		err := crudClient.PatchBulk(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})

	t.Run("correctly returns if crud returns 200 with additional headers to proxy", func(t *testing.T) {
		expectedResponseBody := ResponseBody{
			Bar: "some",
		}

		headersToProxy := http.Header{}
		headersToProxy.Set("request-id", "123")
		headersToProxy.Set("taz", "ok")

		ctx = helpers.AddHeadersToProxyToContext(ctx, headersToProxy)

		MockPatchBulk(t, usersCrudBaseURL, 200, expectedResponseBody, headersToProxy)

		var responseBody ResponseBody
		err := crudClient.PatchBulk(ctx, "", &responseBody)

		require.NoError(t, err)
		require.Equal(t, expectedResponseBody, responseBody)
	})
}

func TestIsHealthy(t *testing.T) {
	usersCrudBaseURL := "http://crud.example.org/my-coll-name/"

	crudClient, err := New(usersCrudBaseURL)
	require.NoError(t, err)
	require.NotNil(t, crudClient)

	t.Run("ok", func(t *testing.T) {
		MockIsHealthy(t, usersCrudBaseURL, 200, nil)

		err := crudClient.IsHealthy(context.Background())
		require.NoError(t, err)
	})

	t.Run("ok - proxy headers", func(t *testing.T) {
		h := http.Header{}
		h.Set("foo", "bar")
		MockIsHealthy(t, usersCrudBaseURL, 200, h)

		ctx := context.Background()
		ctx = helpers.AddHeadersToProxyToContext(ctx, h)

		err := crudClient.IsHealthy(ctx)
		require.NoError(t, err)
	})

	t.Run("ko", func(t *testing.T) {
		MockIsHealthy(t, usersCrudBaseURL, 503, nil)

		err := crudClient.IsHealthy(context.Background())
		require.Error(t, err)
	})
}
