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
	"encoding/json"
	"net/http"
	"strings"
)

const ContentTypeHeaderKey = "content-type"
const JSONContentTypeHeader = "application/json"

func UnmarshalHeader(headers http.Header, headerKey string, v interface{}) (bool, error) {
	headerValueStringified := headers.Get(headerKey)
	if headerValueStringified != "" {
		err := json.Unmarshal([]byte(headerValueStringified), &v)
		return err == nil, err
	}
	return false, nil
}

func HasApplicationJSONContentType(headers http.Header) bool {
	return strings.HasPrefix(headers.Get(ContentTypeHeaderKey), JSONContentTypeHeader)
}
