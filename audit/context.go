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
	"fmt"
)

type cacheKey struct{}

func WithAuditCache(ctx context.Context, agent Agent) context.Context {
	return context.WithValue(ctx, cacheKey{}, agent.Cache())
}

func GetAuditCache(ctx context.Context) (AuditCache, error) {
	auditCache, ok := ctx.Value(cacheKey{}).(AuditCache)
	if !ok {
		return nil, fmt.Errorf("todo")
	}
	return auditCache, nil
}
