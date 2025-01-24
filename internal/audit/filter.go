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

import "strings"

type Filter interface {
	Skip(Audit) bool
}

type FilterOptions struct {
	ExcludeVerbs []string `json:"excludeVerbs"`
}

type TrailFilter struct {
	o FilterOptions
}

func NewFilter(o FilterOptions) Filter {
	return &TrailFilter{
		o: o,
	}
}

func (t *TrailFilter) Skip(data Audit) bool {
	if len(t.o.ExcludeVerbs) > 0 {
		for _, verb := range t.o.ExcludeVerbs {
			if strings.EqualFold(data.Request.Verb, verb) {
				return true
			}
		}
	}
	return false
}
