// Copyright 2021 Mia srl
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

package utils

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/samber/lo"
)

const GENERIC_BUSINESS_ERROR_MESSAGE = "Internal server error, please try again later"
const NO_PERMISSIONS_ERROR_MESSAGE = "You do not have permissions to access this feature, contact the administrator for more information."

var ErrFileLoadFailed = errors.New("file loading failed")

var Contains = lo.Contains[string]

func FilterList(list []string, valuesToFilter []string) []string {
	differenceValues, _ := lo.Difference(list, valuesToFilter)
	return differenceValues
}

func SanitizeString(input string) string {
	sanitized := strings.Replace(input, "\n", "", -1)
	sanitized = strings.Replace(sanitized, "\r", "", -1)
	return sanitized
}

var Union = lo.Union[string]

func ReadFile(path string) ([]byte, error) {
	//#nosec G304 -- This is an expected behaviour
	fileContentByte, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFileLoadFailed, err.Error())
	}
	return fileContentByte, nil
}
