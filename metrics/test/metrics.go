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

package metricstest

import (
	"github.com/rond-authz/rond/metrics"
)

type Entry struct {
	Name   string
	Labels metrics.Labels
	Value  float64
}

type Entries []Entry

type Hook struct {
	Entries Entries
}

func (h *Hook) setValueToLastEntry(v float64) {
	h.Entries[len(h.Entries)-1].Value = v
}

func (h *Hook) AllEntries() Entries {
	return h.Entries
}

func New() (*metrics.Metrics, *Hook) {
	duration := histogramVec{
		Namespace: metrics.Prefix,
		Name:      metrics.PolicyEvalDuration,
		Labels:    []string{"policy_name"},

		hook: &Hook{},
	}

	m := &metrics.Metrics{
		PolicyEvaluationDurationMilliseconds: duration,
	}

	return m, duration.hook
}

type histogramVec struct {
	Namespace string
	Name      string
	Labels    []string

	hook *Hook
}

type observer struct {
	hook *Hook
}

func (o observer) Observe(v float64) {
	o.hook.setValueToLastEntry(v)
}

func (h histogramVec) With(labels metrics.Labels) metrics.Observer {
	h.hook.Entries = append(h.hook.Entries, Entry{
		Name:   h.Name,
		Labels: labels,
	})

	return observer{hook: h.hook}
}
