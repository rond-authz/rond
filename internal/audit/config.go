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
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

var (
	ErrConfigLoadFailed = errors.New("failed to read configuration file")
)

type Config struct {
	FilterOptions FilterOptions `json:"filterOptions"`
}

func LoadConfiguration(path string) (Config, error) {
	//#nosec G304 -- This is an expected behaviour
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrConfigLoadFailed, err)
	}
	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		return Config{}, fmt.Errorf("%w: %s", ErrConfigLoadFailed, err)

	}
	return config, nil
}
