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
	"testing"

	"github.com/rond-authz/rond/internal/testutils"

	"github.com/stretchr/testify/require"
)

var auditCollectionName = "audit-collection"

func TestMongoDBAgent(t *testing.T) {
	t.Run("test NewMongoDBAgent", func(t *testing.T) {
		agent := NewMongoDBAgent(&testutils.MockMongoClient{}, auditCollectionName)
		require.NotNil(t, agent)
	})

	t.Run("Trace saves the audit trail in the database", func(t *testing.T) {
		client, dbName := testutils.GetAndDisposeMongoClient(t)
		agent := NewMongoDBAgent(
			&testutils.MockMongoClient{ActualClient: client, DBName: dbName},
			auditCollectionName,
		)

		agent.Trace(context.Background(), Audit{
			AggregationID: "some-request-id",
		})

		cursor, err := client.
			Database(dbName).
			Collection(auditCollectionName).
			Find(context.Background(), map[string]any{})
		require.NoError(t, err)

		var results []Audit
		require.NoError(t, cursor.All(context.Background(), &results))

		require.Len(t, results, 1)
		require.Equal(t, "some-request-id", results[0].AggregationID)
	})

	t.Run("trace is stored with proper serialization", func(t *testing.T) {
		client, dbName := testutils.GetAndDisposeMongoClient(t)
		agent := NewMongoDBAgent(
			&testutils.MockMongoClient{ActualClient: client, DBName: dbName},
			auditCollectionName,
		)

		agent.Trace(context.Background(), Audit{
			AggregationID: "some-request-id",
		})

		result := client.
			Database(dbName).
			Collection(auditCollectionName).
			FindOne(
				context.Background(),
				map[string]any{"aggregationId": "some-request-id"},
			)
		require.NotNil(t, result)

		var rawResult map[string]any
		require.NoError(t, result.Decode(&rawResult))
		require.Equal(t, "some-request-id", rawResult["aggregationId"])
	})
}