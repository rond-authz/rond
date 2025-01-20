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
	"slices"

	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"
)

const (
	AgentStorageLog     = "log"
	AgentStorageMongoDB = "mongodb"
)

type MongoAgentPoolOptions struct {
	Client         types.MongoClient
	CollectionName string
}

type AgentPoolOptions struct {
	Logger         logging.Logger
	Labels         Labels
	Storages       []string
	MongoDBStorage MongoAgentPoolOptions
}

func NewAgentPool(options AgentPoolOptions) AgentPool {
	return &agentPool{
		options: options,
	}
}

type agentPool struct {
	options AgentPoolOptions
}

func (c *agentPool) New() Agent {
	if len(c.options.Storages) == 0 {
		return &noopAgent{}
	}

	agents := make([]Agent, 0)
	if includes(c.options.Storages, AgentStorageLog) {
		agents = append(
			agents,
			NewLogAgent(c.options.Logger, c.options.Labels),
		)
	}

	if includes(c.options.Storages, AgentStorageMongoDB) && c.options.MongoDBStorage.Client != nil {
		agents = append(
			agents,
			NewMongoDBAgent(
				c.options.MongoDBStorage.Client,
				c.options.MongoDBStorage.CollectionName,
			),
		)
	}

	if len(agents) == 0 {
		return &noopAgent{}
	}

	return newCompoundAgent(agents...)
}

func includes(slice []string, value string) bool {
	return slices.Contains(slice, value)
}
