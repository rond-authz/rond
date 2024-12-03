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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyDataFromPolicy(t *testing.T) {
	t.Run("sets reserved + custom label", func(t *testing.T) {
		a := auditToPrint{}
		a.applyDataFromPolicy(map[string]any{
			"authorization.permission": "my-permission",
			"authorization.binding":    "my-binding",
			"authorization.role":       "my-role",
			"some-custom-label":        "value",
		})
		require.Equal(t, "my-permission", a.Authorization.Permission)
		require.Equal(t, "my-binding", a.Authorization.BindingID)
		require.Equal(t, "my-role", a.Authorization.RoleID)
		require.Equal(t, "value", a.Labels["some-custom-label"])
	})

	t.Run("reserved keys are not set as label", func(t *testing.T) {
		a := auditToPrint{}
		a.applyDataFromPolicy(map[string]any{
			"authorization.permission": "my-permission",
			"authorization.binding":    "my-binding",
			"authorization.role":       "my-role",
			"some-custom-label":        "value",
		})
		require.Len(t, a.Labels, 1)
		require.Equal(t, "value", a.Labels["some-custom-label"])
	})

	t.Run("ignores invalid permission", func(t *testing.T) {
		a := auditToPrint{}
		a.applyDataFromPolicy(map[string]any{
			"authorization.permission": []string{"my-permission"},
		})
		require.Equal(t, "", a.Authorization.Permission)
	})

	t.Run("ignores invalid binding", func(t *testing.T) {
		a := auditToPrint{}
		a.applyDataFromPolicy(map[string]any{
			"authorization.binding": []string{"my-binding"},
		})
		require.Equal(t, "", a.Authorization.BindingID)
	})

	t.Run("ignores invalid roleId", func(t *testing.T) {
		a := auditToPrint{}
		a.applyDataFromPolicy(map[string]any{
			"authorization.role": []string{"my-role"},
		})
		require.Equal(t, "", a.Authorization.RoleID)
	})

	t.Run("overrides previously set label", func(t *testing.T) {
		a := auditToPrint{
			Labels: map[string]any{
				"a": "boring",
			},
		}
		a.applyDataFromPolicy(map[string]any{
			"a": "funny",
		})
		require.Equal(t, "funny", a.Labels["a"])
	})
}
