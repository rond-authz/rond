package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	PolicyEvaluationDurationMilliseconds *prometheus.HistogramVec
}

func SetupMetricsOrDie(prefix string) Metrics {
	m := Metrics{
		PolicyEvaluationDurationMilliseconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: prefix,
			Name:      "policy_evaluation_duration_milliseconds",
			Help:      "A histogram of the policy evaluation durations in milliseconds.",
			Buckets:   prometheus.ExponentialBucketsRange(0.1, 500, 10),
		}, []string{"policy_name"}),
	}

	return m
}

func (m Metrics) MustRegister(reg prometheus.Registerer) Metrics {
	reg.MustRegister(
		m.PolicyEvaluationDurationMilliseconds,
	)

	return m
}
