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
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestMetrics(t *testing.T) {
	t.Run("setup and register metrics", func(t *testing.T) {
		m := SetupMetrics("test_prefix")
		registry := prometheus.NewPedanticRegistry()
		m.MustRegister(registry)

		t.Run("PolicyEvaluationDurationMilliseconds", func(t *testing.T) {
			m.PolicyEvaluationDurationMilliseconds.WithLabelValues("myPolicyName").Observe(10)

			metadata := `
			# HELP test_prefix_policy_evaluation_duration_milliseconds A histogram of the policy evaluation durations in milliseconds.
			# TYPE test_prefix_policy_evaluation_duration_milliseconds histogram
`
			expected := `
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="1"} 0
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="5"} 0
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="10"} 1
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="50"} 1
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="100"} 1
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="250"} 1
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="500"} 1
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="+Inf"} 1
			test_prefix_policy_evaluation_duration_milliseconds_sum{policy_name="myPolicyName"} 10
			test_prefix_policy_evaluation_duration_milliseconds_count{policy_name="myPolicyName"} 1
`

			require.NoError(t, testutil.CollectAndCompare(m.PolicyEvaluationDurationMilliseconds, strings.NewReader(metadata+expected), "test_prefix_policy_evaluation_duration_milliseconds"))
		})
	})
}
