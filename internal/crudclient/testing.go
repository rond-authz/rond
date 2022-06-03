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
	"net/http"
	"testing"

	"gopkg.in/h2non/gock.v1"
)

// MockUpsertWithQueryParameters mocks upsert to a collection.
func getHeadersMap(headers http.Header) map[string]string {
	requestHeadersMap := map[string]string{}
	if len(headers) != 0 {
		for name, values := range headers {
			requestHeadersMap[name] = values[0]
		}
	}
	return requestHeadersMap
}

// MockGetByID mocks get in a collection.
func MockGet(t *testing.T, baseURL string, statusCode int, responseBody interface{}, headersToProxy http.Header) {
	t.Helper()
	t.Cleanup(func() {
		gockCleanup(t)
	})
	gock.DisableNetworking()

	gock.New(baseURL).
		MatchHeaders(getHeadersMap(headersToProxy)).
		Reply(statusCode).
		JSON(responseBody)
}

// MockPost mocks post in a collection.
func MockPost(t *testing.T, baseURL string, statusCode int, responseBody interface{}, headersToProxy http.Header) {
	t.Helper()
	t.Cleanup(func() {
		gockCleanup(t)
	})
	gock.DisableNetworking()

	gock.New(baseURL).
		MatchHeaders(getHeadersMap(headersToProxy)).
		Reply(statusCode).
		JSON(responseBody)
}

// MockDelete mocks post in a collection.
func MockDelete(t *testing.T, baseURL string, statusCode int, responseBody interface{}, headersToProxy http.Header) {
	t.Helper()
	t.Cleanup(func() {
		gockCleanup(t)
	})
	gock.DisableNetworking()

	gock.New(baseURL).
		MatchHeaders(getHeadersMap(headersToProxy)).
		Reply(statusCode).
		JSON(responseBody)
}

// MockPatchBulk mocks post in a collection.
func MockPatchBulk(t *testing.T, baseURL string, statusCode int, responseBody interface{}, headersToProxy http.Header) {
	t.Helper()
	t.Cleanup(func() {
		gockCleanup(t)
	})
	gock.DisableNetworking()

	gock.New(baseURL).
		MatchHeaders(getHeadersMap(headersToProxy)).
		Reply(statusCode).
		JSON(responseBody)
}

// MockIsHealthy mock the healthy function
func MockIsHealthy(t *testing.T, baseURL string, statusCode int, headersToProxy http.Header) {
	t.Helper()
	t.Cleanup(func() {
		gockCleanup(t)
	})
	gock.DisableNetworking()

	responseBody := map[string]interface{}{
		"status": "OK",
	}
	if statusCode >= 300 {
		responseBody = map[string]interface{}{
			"status": "KO",
		}
	}

	gock.New(baseURL).
		MatchHeaders(getHeadersMap(headersToProxy)).
		Get("/-/healthz").
		Reply(statusCode).
		JSON(responseBody)
}

func gockCleanup(t *testing.T) {
	t.Helper()

	if !gock.IsDone() {
		gock.OffAll()
		t.Fatal("fails to mock crud")
	}
	gock.Off()
}
