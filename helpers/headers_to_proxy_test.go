/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package helpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestAddHeadersToProxyToContext(t *testing.T) {
	t.Run("correctly set nil headers in context", func(t *testing.T) {
		ctx := context.Background()
		ctx = AddHeadersToProxyToContext(ctx, nil)

		requestHeadersToProxy, ok := ctx.Value(requestHeadersToProxy{}).(http.Header)
		require.True(t, ok)
		require.Len(t, requestHeadersToProxy, 0)
	})

	t.Run("correctly set headers in context", func(t *testing.T) {
		ctx := context.Background()
		h := http.Header{}
		h.Set("foo", "bar")
		ctx = AddHeadersToProxyToContext(ctx, h)

		requestHeadersToProxy, ok := ctx.Value(requestHeadersToProxy{}).(http.Header)
		require.True(t, ok)
		require.Len(t, requestHeadersToProxy, 1)
		require.Equal(t, requestHeadersToProxy.Get("foo"), "bar")
	})
}

func TestAddHeadersToProxyMiddleware(t *testing.T) {
	var called = false
	t.Run("set empty headers if headers to proxy is nil", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		testMockMiddlewareInvocation(handler, nil)

		require.True(t, called)
	})

	t.Run("set empty headers if headers to proxy is empty", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})
		testMockMiddlewareInvocation(handler, []string{})

		require.True(t, called)
	})

	t.Run("set headers proxy in context", func(t *testing.T) {
		requestHeaders := http.Header{}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			requestHeaders = r.Context().Value(requestHeadersToProxy{}).(http.Header)
		})
		h := testMockMiddlewareInvocation(handler, []string{"foo", "x-request-id", "x-forwarded-for", "x-forwarded-host"})

		require.True(t, called)
		require.Equal(t, h, requestHeaders)
	})
}

func TestSetHeadersToProxy(t *testing.T) {
	t.Run("not panic if context not contains headersToProxy key", func(t *testing.T) {
		ctx := context.Background()
		headers := http.Header{}
		SetHeadersToProxy(ctx, headers)

		require.Len(t, headers, 0)
	})

	t.Run("not set header if empty headers to proxy", func(t *testing.T) {
		ctx := context.Background()
		requestHeaders := http.Header{}
		ctx = AddHeadersToProxyToContext(ctx, requestHeaders)

		headers := http.Header{}
		SetHeadersToProxy(ctx, headers)

		require.Len(t, headers, 0)
	})

	t.Run("set headers correctly", func(t *testing.T) {
		ctx := context.Background()
		requestHeaders := http.Header{}
		requestHeaders.Set("foo", "bar")
		requestHeaders.Set("taz", "ok")
		ctx = AddHeadersToProxyToContext(ctx, requestHeaders)

		headers := http.Header{}
		SetHeadersToProxy(ctx, headers)

		require.Len(t, headers, 2)
		require.Equal(t, headers.Get("foo"), "bar")
		require.Equal(t, headers.Get("taz"), "ok")
	})
}

func testMockMiddlewareInvocation(next http.HandlerFunc, headersToAdd []string) http.Header {
	// create a request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("x-request-id", "123")
	req.Header.Add("x-forwarded-for", "my-ip")
	req.Header.Add("x-forwarded-host", "my-host")

	logger, _ := test.NewNullLogger()

	handler := AddHeadersToProxyMiddleware(logger, headersToAdd)
	// invoke the handler
	server := handler(next)
	// Create a response writer
	writer := httptest.NewRecorder()
	// Serve HTTP server
	server.ServeHTTP(writer, req)

	return req.Header
}
