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
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTraceFilterApply(t *testing.T) {
	testCases := []struct {
		name     string
		options  FilterOptions
		data     Audit
		expected bool
	}{
		{
			name: "returns true for matching excluded verb",
			options: FilterOptions{
				ExcludeVerbs: []string{http.MethodGet},
			},
			expected: true,
			data: Audit{
				Request: RequestInfo{
					Verb: http.MethodGet,
				},
			},
		},
		{
			name: "returns true for matching excluded verb (case insensitive)",
			options: FilterOptions{
				ExcludeVerbs: []string{"get"},
			},
			expected: true,
			data: Audit{
				Request: RequestInfo{
					Verb: http.MethodGet,
				},
			},
		},
		{
			name:     "returns false if no match from options is found",
			options:  FilterOptions{},
			expected: false,
			data:     Audit{},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("#%d: %s", i, tc.name), func(t *testing.T) {
			require.Equal(
				t,
				tc.expected,
				NewFilter(tc.options).Skip(tc.data),
			)
		})
	}
}
