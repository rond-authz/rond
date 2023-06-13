package core

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

func TrailingSlashMiddleware(ignoreTrailingSlash bool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if ignoreTrailingSlash {
				r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
			}

			next.ServeHTTP(w, r)
		})
	}
}
