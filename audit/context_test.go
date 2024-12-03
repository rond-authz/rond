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

func TestContext(t *testing.T) {
	t.Run("add to context and get", func(t *testing.T) {
		ctx := context.Background()

		agent := &noopAgent{}

		retrievedAgent, err := GetAuditCache(WithAuditCache(ctx, agent))

		require.NoError(t, err)
		require.NotNil(t, retrievedAgent)
	})

	t.Run("get cache failure", func(t *testing.T) {
		_, err := GetAuditCache(context.Background())
		require.Error(t, err, "failed to extract audit cache from context")

	})
}
