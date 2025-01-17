// Copyright 2024 Mia srl
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
	"testing"

	rondlogrus "github.com/rond-authz/rond/logging/logrus"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestLogAgent(t *testing.T) {
	l, hook := test.NewNullLogger()
	agent := NewLogAgent(rondlogrus.NewLogger(l), nil)

	agent.Cache().Store(Data{
		"authorization.permission": "my-permission",
		"authorization.binding":    "my-binding",
		"authorization.role":       "my-role",
		"my-label-key":             "my-label-value",
	})
	agent.Trace(context.Background(), Audit{
		AggregationID: "the-aggregation-id",
		Authorization: AuthzInfo{
			Allowed:    true,
			PolicyName: "some_policy",
		},
		Subject: SubjectInfo{
			ID:     "some user",
			Groups: []string{"g1", "g2"},
		},
		Request: RequestInfo{Body: []byte("some body")},
	})

	entries := hook.AllEntries()
	require.Len(t, entries, 1)

	entry := entries[0]
	require.Equal(t, "audit trail", entry.Message)

	trailData := entry.Data["trail"]
	trailDataMap := trailData.(map[string]any)

	require.NotEmpty(t, trailDataMap["id"])
	delete(trailDataMap, "id")

	require.Equal(t, map[string]any{
		"aggregationId": "the-aggregation-id",
		"authorization": map[string]any{
			"allowed":    true,
			"policyName": "some_policy",
			"permission": "my-permission",
			"binding":    "my-binding",
			"roleId":     "my-role",
		},
		"labels": map[string]any{
			"my-label-key": "my-label-value",
		},
		"request": map[string]any{
			"body": []byte("some body"),
		},
		"subject": map[string]any{
			"groups": []string{"g1", "g2"},
			"id":     "some user",
		},
	}, trailData)
}

func TestLogAgentWithGlobalLabels(t *testing.T) {
	l, hook := test.NewNullLogger()

	agent := NewLogAgent(rondlogrus.NewLogger(l), Labels{
		AuditAdditionalDataRequestTargetServiceKey: "some-service",
		"some-label": "label_val",
	})

	agent.Cache().Store(Data{
		"authorization.permission": "my-permission",
		"authorization.binding":    "my-binding",
		"authorization.role":       "my-role",
		"my-label-key":             "my-label-value",
	})
	agent.Trace(context.Background(), Audit{
		AggregationID: "the-aggregation-id",
		Authorization: AuthzInfo{
			Allowed:    true,
			PolicyName: "some_policy",
		},
		Subject: SubjectInfo{
			ID:     "some user",
			Groups: []string{"g1", "g2"},
		},
		Request: RequestInfo{Body: []byte("some body")},
	})

	entries := hook.AllEntries()
	require.Len(t, entries, 1)

	entry := entries[0]
	require.Equal(t, "audit trail", entry.Message)

	trailData := entry.Data["trail"]
	trailDataMap := trailData.(map[string]any)

	require.NotEmpty(t, trailDataMap["id"])
	delete(trailDataMap, "id")

	require.Equal(t, map[string]any{
		"aggregationId": "the-aggregation-id",
		"authorization": map[string]any{
			"allowed":    true,
			"policyName": "some_policy",
			"permission": "my-permission",
			"binding":    "my-binding",
			"roleId":     "my-role",
		},
		"labels": map[string]any{
			"some-label":   "label_val",
			"my-label-key": "my-label-value",
		},
		"request": map[string]any{
			"body":              []byte("some body"),
			"targetServiceName": "some-service",
		},
		"subject": map[string]any{
			"groups": []string{"g1", "g2"},
			"id":     "some user",
		},
	}, trailData)
}
