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
