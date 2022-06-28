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
	"strings"

	"github.com/elliotchance/pie/pie"
)

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func AppendUnique(element *[]string, elementToAppend string) {
	if !Contains((*element), elementToAppend) {
		(*element) = append((*element), elementToAppend)
	}
}

func FilterList(list []string, valuesToFilter []string) []string {
	pieList := pie.Strings(list)
	newList := pieList.Filter(func(listItem string) bool {
		return !Contains(valuesToFilter, listItem)
	})
	return newList
}

func SanitizeString(input string) string {
	sanitized := strings.Replace(input, "\n", "", -1)
	sanitized = strings.Replace(sanitized, "\r", "", -1)
	return sanitized
}
