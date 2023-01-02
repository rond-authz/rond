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

package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var MetricsRoutePath = "/-/rond/metrics"

func MetricsRoute(r *mux.Router, registry *prometheus.Registry) {
	r.Handle(MetricsRoutePath, promhttp.InstrumentMetricHandler(
		registry,
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{
			Registry:          registry,
			EnableOpenMetrics: true,
		}),
	))
}

type metricsContextKey struct{}

// RequestMiddleware is a gorilla/mux middleware used to inject
// metrics struct into requests.
func RequestMiddleware(m Metrics) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithValue(r.Context(), m)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func WithValue(ctx context.Context, m Metrics) context.Context {
	return context.WithValue(ctx, metricsContextKey{}, m)
}

func GetFromContext(ctx context.Context) (Metrics, error) {
	m, ok := ctx.Value(metricsContextKey{}).(Metrics)
	if !ok {
		return Metrics{}, fmt.Errorf("invalid metrics in context")
	}
	return m, nil
}
