/*
 * Copyright © 2022-present Mia s.r.l.
 * All rights reserved
 */

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
