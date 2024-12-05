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

package utils

import (
	"reflect"
	"strings"
)

const OmitEmptyTagOption = "omitempty"

func parseTag(tag string) (string, string) {
	tag, opt, _ := strings.Cut(tag, ",")
	return tag, opt
}

func isEmptyValue(v reflect.Value) bool {
	kind := v.Kind()
	switch kind {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}

func ToMap(tagTitle string, val interface{}) map[string]any {
	var data map[string]any = make(map[string]any)
	varType := reflect.TypeOf(val)
	if varType.Kind() != reflect.Struct {
		return nil
	}

	value := reflect.ValueOf(val)
	for i := 0; i < varType.NumField(); i++ {
		if !value.Field(i).CanInterface() {
			// Skip unexported fields
			continue
		}
		fullTag, ok := varType.Field(i).Tag.Lookup(tagTitle)
		tag, opt := parseTag(fullTag)

		var fieldName string
		if ok && len(tag) > 0 {
			fieldName = tag
		} else {
			fieldName = varType.Field(i).Name
		}

		if varType.Field(i).Type.Kind() != reflect.Struct {
			if isEmptyValue(value.Field(i)) && opt == OmitEmptyTagOption {
				continue
			}
			data[fieldName] = value.Field(i).Interface()
		} else {
			data[fieldName] = ToMap(tagTitle, value.Field(i).Interface())
		}
	}

	return data
}
