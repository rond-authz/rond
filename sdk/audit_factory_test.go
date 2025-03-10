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

package sdk

import (
	"context"
	"testing"

	"github.com/rond-authz/rond/internal/audit"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestBuildAuditAgent(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		res := buildAuditAgent(nil, nil)
		require.NotNil(t, res)
	})

	t.Run("nil evaluator options", func(t *testing.T) {
		res := buildAuditAgent(&Options{
			EvaluatorOptions: nil,
		}, nil)
		require.NotNil(t, res)
	})

	t.Run("nil logger", func(t *testing.T) {
		res := buildAuditAgent(&Options{
			EvaluatorOptions: &EvaluatorOptions{
				EnableAuditTracing: false,
			},
		}, nil)
		require.NotNil(t, res)
	})

	t.Run("with setup trace", func(t *testing.T) {
		log, hook := test.NewNullLogger()
		res := buildAuditAgent(&Options{
			EvaluatorOptions: &EvaluatorOptions{
				EnableAuditTracing: true,
				AuditTracingOptions: AuditEvaluatorOptions{
					StorageMode: []string{audit.AgentStorageLog},
				},
			},
		}, rondlogrus.NewEntry(logrus.NewEntry(log)))
		require.NotNil(t, res)

		agent := res.New()

		agent.Cache().Store(audit.Data{"test": "123"})
		agent.Trace(context.Background(), audit.Audit{
			AggregationID: "a-id",
		})
		require.Len(t, hook.Entries, 1)
	})
}
