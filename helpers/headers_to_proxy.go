/*
 * Copyright © 2021-present Mia s.r.l.
 * All rights reserved
 */

package helpers

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type requestHeadersToProxy struct{}

func SetHeadersToProxy(ctx context.Context, headers http.Header) {
	reqHeadersToProxy, ok := ctx.Value(requestHeadersToProxy{}).(http.Header)
	if ok && len(reqHeadersToProxy) != 0 {
		for name := range reqHeadersToProxy {
			headers.Set(name, reqHeadersToProxy.Get(name))
		}
	}
}

func AddHeadersToProxyMiddleware(logger *logrus.Logger, headerToAdd []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headersToProxy := http.Header{}
			for _, h := range headerToAdd {
				hValue := r.Header.Get(h)
				if len(hValue) > 0 {
					headersToProxy.Set(h, hValue)
				}
			}
			ctx := AddHeadersToProxyToContext(r.Context(), headersToProxy)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AddHeadersToProxyToContext(ctx context.Context, value http.Header) context.Context {
	return context.WithValue(ctx, requestHeadersToProxy{}, value)
}
