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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfiguration(t *testing.T) {
	t.Run("should fail on missing file", func(t *testing.T) {
		_, err := LoadConfiguration("../../mocks/audit-configurations/missing.json")
		require.ErrorIs(t, err, ErrConfigLoadFailed)
	})

	t.Run("should fail on non-json config file", func(t *testing.T) {
		_, err := LoadConfiguration("./config.go")
		require.ErrorIs(t, err, ErrConfigLoadFailed)
	})

	t.Run("should return a Config struct", func(t *testing.T) {
		config, err := LoadConfiguration("../../mocks/audit-configurations/config.json")
		require.NoError(t, err)
		require.NotEmpty(t, config)

		require.Equal(t, Config{
			FilterOptions: FilterOptions{
				ExcludeVerbs: []string{"PUT"},
			},
		}, config)
	})
}
