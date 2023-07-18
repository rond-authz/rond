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

const (
	Prefix = "rond"

	PolicyEvalDuration = "policy_evaluation_duration_milliseconds"
)

type Labels map[string]string

type Observer interface {
	Observe(float64)
}

type HistogramVec interface {
	With(labels Labels) Observer
}

type Metrics struct {
	PolicyEvaluationDurationMilliseconds HistogramVec
}

type noopHistogram struct{}

func (h noopHistogram) With(labels Labels) Observer {
	return noopObserver{}
}

type noopObserver struct{}

func (o noopObserver) Observe(float64) {}

func NoOpMetrics() *Metrics {
	return &Metrics{
		PolicyEvaluationDurationMilliseconds: noopHistogram{},
	}
}
