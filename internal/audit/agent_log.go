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

	"github.com/rond-authz/rond/logging"
)

func NewLogAgent(l logging.Logger, labels Labels) Agent {
	agent := &logAgent{
		l:     l,
		cache: &SingleRecordCache{},
	}
	if labels != nil {
		agent.cache.Store(labels)
	}
	return agent
}

type logAgent struct {
	l     logging.Logger
	cache AuditCache
}

func (a *logAgent) Trace(_ context.Context, auditInput Audit) error {
	trail := auditInput.toPrint(a.cache.Load()).serialize()
	a.l.
		WithField("trail", trail).
		Info("audit trail")
	return nil
}

func (a *logAgent) Cache() AuditCache {
	return a.cache
}
