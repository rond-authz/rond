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
	"testing"

	"github.com/rond-authz/rond/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestAgentPool(t *testing.T) {
	t.Run("test NewAgentPool", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{})
		require.NotNil(t, agentPool)
	})

	t.Run("New returns a noopAgent if no storages are provided", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{})
		agent := agentPool.New()
		require.IsType(t, &noopAgent{}, agent)
	})

	t.Run("New returns a compoundAgent with a single logAgent if storage is provided only with log", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{
			Storages: []string{AgentStorageLog},
		})
		agent := agentPool.New()
		require.IsType(t, &compoundAgent{}, agent)

		compoundAgent := agent.(*compoundAgent)
		require.Len(t, compoundAgent.agents, 1)

		require.IsType(t, &logAgent{}, compoundAgent.agents[0])
	})

	t.Run("New returns a compoundAgent with a single mongoDBAgent if storage is provided only with mongodb", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{
			Storages: []string{AgentStorageMongoDB},
			MongoDBStorage: MongoAgentPoolOptions{
				Client: &testutils.MockMongoClient{},
			},
		})
		agent := agentPool.New()
		require.IsType(t, &compoundAgent{}, agent)

		compoundAgent := agent.(*compoundAgent)
		require.Len(t, compoundAgent.agents, 1)

		require.IsType(t, &mongoDBAgent{}, compoundAgent.agents[0])
	})

	t.Run("New returns a noopAgent if mongodb is the only desired storage no MongoDB client is provided", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{
			Storages: []string{AgentStorageMongoDB},
			MongoDBStorage: MongoAgentPoolOptions{
				Client: nil,
			},
		})
		agent := agentPool.New()
		require.IsType(t, &noopAgent{}, agent)
	})

	t.Run("New returns a compoundAgent with both logAgent and mongoDBAgent if storage uses both", func(t *testing.T) {
		agentPool := NewAgentPool(AgentPoolOptions{
			Storages: []string{AgentStorageLog, AgentStorageMongoDB},
			MongoDBStorage: MongoAgentPoolOptions{
				Client: &testutils.MockMongoClient{},
			},
		})
		agent := agentPool.New()
		require.IsType(t, &compoundAgent{}, agent)

		compoundAgent := agent.(*compoundAgent)
		require.Len(t, compoundAgent.agents, 2)

		require.IsType(t, &logAgent{}, compoundAgent.agents[0])
		require.IsType(t, &mongoDBAgent{}, compoundAgent.agents[1])
	})
}
