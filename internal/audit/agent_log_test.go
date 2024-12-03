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
	agent := NewLogAgent(rondlogrus.NewLogger(l))

	agent.Trace(context.TODO(), Audit{
		AggregationID: "the-aggregation-id",
		Authorization: AuthzInfo{
			Allowed:    true,
			PolicyName: "some_policy",
		},
		Subject: SubjectInfo{
			ID:     "some user",
			Groups: []string{"g1", "g2"},
		},
		RequestBody: []byte("some body"),
	})

	entries := hook.AllEntries()
	require.Len(t, entries, 1)
	require.Equal(t, "audit trail", entries[0].Message)
}
