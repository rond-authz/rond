// Copyright 2025 Mia srl
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

package audit

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompoundAgentTrace(t *testing.T) {
	testCases := []struct {
		name          string
		agents        []Agent
		audit         Audit
		expectedError error
	}{
		{
			name: "single agent",
			agents: []Agent{
				&testAgent{
					AssertTraceFunc: func(_ctx context.Context, a Audit) {
						require.Equal(t, "aggregation-id", a.AggregationID)
					},
				},
			},
			audit: Audit{
				AggregationID: "aggregation-id",
			},
		},
		{
			name: "multiple agents",
			agents: []Agent{
				&testAgent{
					AssertTraceFunc: func(_ctx context.Context, a Audit) {
						require.Equal(t, "aggregation-id", a.AggregationID)
					},
				},
				&testAgent{
					AssertTraceFunc: func(_ctx context.Context, a Audit) {
						require.Equal(t, "aggregation-id", a.AggregationID)
					},
				},
			},
			audit: Audit{
				AggregationID: "aggregation-id",
			},
		},
		{
			name: "single agents failure",
			agents: []Agent{
				&testAgent{
					TraceError: fmt.Errorf("agent 1 error message"),
				},
				&testAgent{
					AssertTraceFunc: func(_ctx context.Context, a Audit) {
						require.Equal(t, "aggregation-id", a.AggregationID)
					},
				},
			},
			audit: Audit{
				AggregationID: "aggregation-id",
			},
			expectedError: fmt.Errorf("1/2 agents failed to trace: agent 1 error message"),
		},
		{
			name: "multiple agents failure",
			agents: []Agent{
				&testAgent{
					TraceError: fmt.Errorf("agent 1 error message"),
				},
				&testAgent{
					TraceError: fmt.Errorf("agent 2 error message"),
				},
			},
			audit: Audit{
				AggregationID: "aggregation-id",
			},
			expectedError: fmt.Errorf("2/2 agents failed to trace: agent 1 error message; agent 2 error message"),
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case#%d: %s", i+1, tc.name), func(t *testing.T) {
			compoundAgent := newCompoundAgent(tc.agents...)

			err := compoundAgent.Trace(context.Background(), tc.audit)
			if tc.expectedError == nil {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}
}

func TestCompoundAgentCacheLoad(t *testing.T) {
	testCases := []struct {
		name   string
		agents []Agent
	}{
		{
			name: "single agent",
			agents: []Agent{
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a1-k1": "a1-v1"},
					},
				},
			},
		},
		{
			name: "multiple agents",
			agents: []Agent{
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a1-k1": "a1-v1"},
					},
				},
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a2-k1": "a2-v2"},
					},
				},
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case#%d: %s", i+1, tc.name), func(t *testing.T) {
			compoundAgent := newCompoundAgent(tc.agents...)

			cache := compoundAgent.Cache()
			require.NotNil(t, cache)

			for _, agent := range tc.agents {
				for k, v := range agent.Cache().Load() {
					require.Equal(t, v, cache.Load()[k])
				}
			}
		})
	}
}

func TestCompoundAgentCacheStore(t *testing.T) {
	testCases := []struct {
		name        string
		agents      []Agent
		dataToStore Data
	}{
		{
			name:        "single agent",
			dataToStore: map[string]interface{}{"new-data": "new-value"},
			agents: []Agent{
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a1-k1": "a1-v1"},
					},
				},
			},
		},
		{
			name:        "multiple agents",
			dataToStore: map[string]interface{}{"new-data": "new-value"},
			agents: []Agent{
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a1-k1": "a1-v1"},
					},
				},
				&testAgent{
					MockCache: &SingleRecordCache{
						data: map[string]interface{}{"a2-k1": "a2-v2"},
					},
				},
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("case#%d: %s", i+1, tc.name), func(t *testing.T) {
			compoundAgent := newCompoundAgent(tc.agents...)

			cache := compoundAgent.Cache()
			cache.Store(tc.dataToStore)

			for _, agent := range tc.agents {
				agentCache := agent.Cache()
				require.Equal(t, "new-value", agentCache.Load()["new-data"])
			}
		})
	}
}
