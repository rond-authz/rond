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

import "context"

type Labels = map[string]any

type Agent interface {
	Trace(context.Context, Audit)
	Cache() AuditCache
	SetGlobalLabels(labels Labels)
}

// noopAgent is a lazy agent that does nothing :(
type noopAgent struct{}

func NewNoopAgent() Agent { return &noopAgent{} }

func (a *noopAgent) Trace(context.Context, Audit)  {}
func (a *noopAgent) Cache() AuditCache             { return &SingleRecordCache{} }
func (a *noopAgent) SetGlobalLabels(labels Labels) {}
