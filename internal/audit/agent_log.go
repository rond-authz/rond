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

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/logging"
)

type agentPool struct {
	l       logging.Logger
	globals map[string]any
}

func (p *agentPool) New() Agent {
	return &logAgent{
		l:       p.l,
		cache:   &SingleRecordCache{},
		globals: p.globals,
	}
}

func (a *agentPool) SetGlobalLabels(labels Labels) {
	a.globals = labels
}

func NewLogAgentPool(l logging.Logger) AgentPool {
	return &agentPool{
		l: l,
	}
}

type logAgent struct {
	l       logging.Logger
	cache   AuditCache
	globals map[string]any
}

func (a *logAgent) Trace(_ context.Context, auditInput Audit) {
	data := a.cache.Load()

	auditData := auditInput.toPrint()
	if a.globals != nil {
		auditData.applyDataFromPolicy(a.globals)
	}

	if data != nil {
		auditData.applyDataFromPolicy(data)
	}

	a.l.
		WithField("trail", utils.ToMap(auditSerializerTagAnnotation, auditData)).
		Info("audit trail")
}

func (a *logAgent) Cache() AuditCache {
	return a.cache
}
