// Copyright 2023 Mia srl
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

package rondprometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rond-authz/rond/metrics"
)

const MetricsPrefix = "rond"

func SetupMetrics(reg prometheus.Registerer) *metrics.Metrics {
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: MetricsPrefix,
		Name:      "policy_evaluation_duration_milliseconds",
		Help:      "A histogram of the policy evaluation durations in milliseconds.",
		Buckets:   []float64{1, 5, 10, 50, 100, 250, 500},
	}, []string{"policy_name"})

	m := &metrics.Metrics{
		PolicyEvaluationDurationMilliseconds: histogramVec{duration},
	}

	reg.MustRegister(
		duration,
	)

	return m
}

type histogramVec struct {
	*prometheus.HistogramVec
}

type observer struct {
	prometheus.Observer
}

func (h histogramVec) With(labels metrics.Labels) metrics.Observer {
	return observer{h.HistogramVec.With(prometheus.Labels(labels))}
}
