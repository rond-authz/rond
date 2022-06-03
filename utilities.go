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

package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rond-authz/rond/types"
)

const ContentTypeHeaderKey = "content-type"
const JSONContentTypeHeader = "application/json"

func hasApplicationJSONContentType(headers http.Header) bool {
	return strings.HasPrefix(headers.Get(ContentTypeHeaderKey), JSONContentTypeHeader)
}

func failResponse(w http.ResponseWriter, technicalError, businessError string) {
	failResponseWithCode(w, http.StatusInternalServerError, technicalError, businessError)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, technicalError, businessError string) {
	w.WriteHeader(statusCode)
	content, err := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Error:      technicalError,
		Message:    businessError,
	})
	if err != nil {
		return
	}

	w.Header().Set(ContentTypeHeaderKey, JSONContentTypeHeader)
	//#nosec G104 -- Intended to avoid disruptive code changes
	w.Write(content)
}

func unmarshalHeader(headers http.Header, headerKey string, v interface{}) (bool, error) {
	headerValueStringified := headers.Get(headerKey)
	if headerValueStringified != "" {
		err := json.Unmarshal([]byte(headerValueStringified), &v)
		return err == nil, err
	}
	return false, nil
}
