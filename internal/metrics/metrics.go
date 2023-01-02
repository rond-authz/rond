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
