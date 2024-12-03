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
