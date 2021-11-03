package main

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestDirectProxyHandler(t *testing.T) {
	t.Run("opens backend server and sends it request using proxy", func(t *testing.T) {
		invoked := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true

			assert.Equal(t, r.URL.Path, "/api", "Mocked Backend: Unexpected path of request url")
			assert.Equal(t, r.URL.RawQuery, "mockQuery=iamquery", "Mocked Backend: Unexpected rawQuery of request url")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api?mockQuery=iamquery", nil)
		assert.Equal(t, err, nil, "Unexpected error")

		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with custom headers", func(t *testing.T) {
		invoked := false
		mockHeader := "CustomHeader"
		mockHeaderValue := "mocked value"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			assert.Equal(t, r.Header.Get(mockHeader), mockHeaderValue, "Mocked Backend: Mocked Header not found")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", nil)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set(mockHeader, mockHeaderValue)
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
	})

	t.Run("sends request with body", func(t *testing.T) {
		invoked := false
		mockBodySting := "I am a body"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			invoked = true
			defer r.Body.Close()
			buf, err := ioutil.ReadAll(r.Body)
			assert.Equal(t, err, nil, "Mocked backend: Unexpected error")
			assert.Equal(t, string(buf), mockBodySting, "Mocked backend: Unexpected Body received")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Mocked Backend Body Example"))
		}))
		defer server.Close()

		body := strings.NewReader(mockBodySting)

		serverURL, _ := url.Parse(server.URL)
		ctx := createContext(t,
			context.Background(),
			EnvironmentVariables{TargetServiceHost: serverURL.Host},
			&OPAEvaluator{PermissionQuery: &mockAllowedOPAEvaluator},
		)

		r, err := http.NewRequestWithContext(ctx, "GET", "http://www.example.com:8080/api", body)
		assert.Equal(t, err, nil, "Unexpected error")
		r.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()

		rbacHandler(w, r)

		assert.Assert(t, invoked, "Handler was not invoked.")
		assert.Equal(t, w.Code, http.StatusOK, "Unexpected status code.")
		buf, err := ioutil.ReadAll(w.Body)
		assert.Equal(t, err, nil, "Unexpected error to read body response")
		assert.Equal(t, string(buf), "Mocked Backend Body Example", "Unexpected body response")
	})
}
