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
	"slices"

	"github.com/rond-authz/rond/logging"
	"github.com/rond-authz/rond/types"
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
	return &compoundAgentPool{
		options: options,
	}
}

type compoundAgentPool struct {
	options AgentPoolOptions
}

func (c *compoundAgentPool) New() Agent {
	agents := make([]Agent, 0)

	if len(c.options.Storages) == 0 {
		return &noopAgent{}
	}

	if includes(c.options.Storages, "log") {
		agents = append(
			agents,
			NewLogAgent(c.options.Logger, c.options.Labels),
		)
	}

	if includes(c.options.Storages, "mongodb") && c.options.MongoDBStorage.Client != nil {
		agents = append(
			agents,
			NewMongoDBAgent(
				c.options.MongoDBStorage.Client,
				c.options.MongoDBStorage.CollectionName,
			),
		)
	}

	return newCompoundAgent(agents...)
}

type compoundAgent struct {
	agents []Agent
}

func newCompoundAgent(agents ...Agent) Agent {
	return &compoundAgent{agents: agents}
}

func (c *compoundAgent) Trace(ctx context.Context, a Audit) error {
	var errors []error
	for _, agent := range c.agents {
		if err := agent.Trace(ctx, a); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		errString := ""
		for _, err := range errors {
			errString += err.Error() + ";"
		}
		return fmt.Errorf("%d/%d agents failed to trace: %s", len(errors), len(c.agents), errString)
	}
	return nil
}

func (c *compoundAgent) Cache() AuditCache {
	return &compoundAuditCache{
		agents: c.agents,
	}
}

type compoundAuditCache struct {
	agents []Agent
}

func (c *compoundAuditCache) Store(d Data) {
	for _, agent := range c.agents {
		agent.Cache().Store(d)
	}
}

func (c *compoundAuditCache) Load() Data {
	dataToReturn := make(Data)
	for _, agent := range c.agents {
		if data := agent.Cache().Load(); data != nil {
			for k, v := range data {
				dataToReturn[k] = v
			}
		}
	}
	return dataToReturn
}

func includes(slice []string, value string) bool {
	return slices.Contains(slice, value)
}
