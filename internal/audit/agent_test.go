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

	"github.com/stretchr/testify/require"
)

func TestNoopAgentDoesNotBreakStuff(t *testing.T) {
	p := NewNoopAgentPool()
	require.NotNil(t, p)

	a := p.New()

	a.Trace(context.Background(), Audit{})

	require.NotNil(t, a.Cache())
}

// testAgent implements Agent interface to provide a mock implementation for testing.
type testAgent struct {
	AssertTraceFunc func(ctx context.Context, a Audit)
	TraceError      error

	MockCache *SingleRecordCache
}

func (t *testAgent) Trace(ctx context.Context, a Audit) error {
	if t.AssertTraceFunc != nil {
		t.AssertTraceFunc(ctx, a)
	}
	return t.TraceError
}

func (t *testAgent) Cache() AuditCache {
	return t.MockCache
}
