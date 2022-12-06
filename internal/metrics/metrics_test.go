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
			test_prefix_policy_evaluation_duration_milliseconds_bucket{policy_name="myPolicyName",le="+Inf"} 1
			test_prefix_policy_evaluation_duration_milliseconds_sum{policy_name="myPolicyName"} 10
			test_prefix_policy_evaluation_duration_milliseconds_count{policy_name="myPolicyName"} 1
`

			require.NoError(t, testutil.CollectAndCompare(m.PolicyEvaluationDurationMilliseconds, strings.NewReader(metadata+expected), "test_prefix_policy_evaluation_duration_milliseconds"))
		})
	})
}
