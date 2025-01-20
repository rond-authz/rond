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
)

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
		for i, err := range errors {
			errString += err.Error()
			if i < len(errors)-1 {
				errString += "; "
			}
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
