package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	PolicyEvaluationDurationMilliseconds *prometheus.HistogramVec
}

func SetupMetrics(prefix string) Metrics {
	m := Metrics{
		PolicyEvaluationDurationMilliseconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: prefix,
			Name:      "policy_evaluation_duration_milliseconds",
			Help:      "A histogram of the policy evaluation durations in milliseconds.",
			Buckets:   []float64{1, 5, 10, 50, 100, 250, 500},
		}, []string{"policy_name"}),
	}

	return m
}

func (m Metrics) MustRegister(reg prometheus.Registerer) Metrics {
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.PolicyEvaluationDurationMilliseconds,
	)

	return m
}
