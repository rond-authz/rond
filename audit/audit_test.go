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
		a := Audit{}
		a.applyDataFromPolicy(map[string]interface{}{
			"authorization.permission": "my-permission",
			"authorization.binding":    "my-binding",
			"authorization.role":       "my-role",
			"some-custom-label":        "value",
		})
		require.Equal(t, "my-permission", a.Authorization.GrantingPermission)
		require.Equal(t, "my-binding", a.Authorization.GrantingBindingID)
		require.Equal(t, "my-role", a.Authorization.GrantingRoleID)
		require.Equal(t, "value", a.Labels["some-custom-label"])
	})

	t.Run("reserved keys are not set as label", func(t *testing.T) {
		a := Audit{}
		a.applyDataFromPolicy(map[string]interface{}{
			"authorization.permission": "my-permission",
			"authorization.binding":    "my-binding",
			"authorization.role":       "my-role",
			"some-custom-label":        "value",
		})
		require.Len(t, a.Labels, 1)
		require.Equal(t, "value", a.Labels["some-custom-label"])
	})

	t.Run("ignores invalid permission", func(t *testing.T) {
		a := Audit{}
		a.applyDataFromPolicy(map[string]interface{}{
			"authorization.permission": []string{"my-permission"},
		})
		require.Equal(t, "", a.Authorization.GrantingPermission)
	})

	t.Run("ignores invalid binding", func(t *testing.T) {
		a := Audit{}
		a.applyDataFromPolicy(map[string]interface{}{
			"authorization.binding": []string{"my-binding"},
		})
		require.Equal(t, "", a.Authorization.GrantingBindingID)
	})

	t.Run("ignores invalid roleId", func(t *testing.T) {
		a := Audit{}
		a.applyDataFromPolicy(map[string]interface{}{
			"authorization.role": []string{"my-role"},
		})
		require.Equal(t, "", a.Authorization.GrantingRoleID)
	})

	t.Run("overrides previously set label", func(t *testing.T) {
		a := Audit{
			Labels: map[string]interface{}{
				"a": "boring",
			},
		}
		a.applyDataFromPolicy(map[string]interface{}{
			"a": "funny",
		})
		require.Equal(t, "funny", a.Labels["a"])
	})
}

func TestToMap(t *testing.T) {
	type SubStruct struct {
		F float64 `audit:"f"`
	}
	type ToConvert struct {
		S  string    `audit:"s"`
		I  int       `audit:"i"`
		St SubStruct `audit:"st"`
		Sl []string  `audit:"sl"`
	}

	c := ToConvert{
		S:  "val",
		I:  42,
		St: SubStruct{F: 4.2},
		Sl: []string{"g1", "g2"},
	}

	result := toMap(c)
	require.Equal(t,
		map[string]interface{}{
			"s": "val",
			"i": 42,
			"st": map[string]interface{}{
				"f": 4.2,
			},
			"sl": []string{"g1", "g2"},
		},
		result,
	)
}