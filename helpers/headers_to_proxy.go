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

func AddHeadersToProxyMiddleware(logger *logrus.Logger, headerNamesToAdd []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headersToProxy := http.Header{}
			for _, headerNameToAdd := range headerNamesToAdd {
				headerValue := r.Header.Get(headerNameToAdd)
				if len(headerValue) > 0 {
					headersToProxy.Set(headerNameToAdd, headerValue)
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
