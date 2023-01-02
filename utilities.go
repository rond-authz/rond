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

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"
)

func failResponse(w http.ResponseWriter, technicalError, businessError string) {
	failResponseWithCode(w, http.StatusInternalServerError, technicalError, businessError)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, technicalError, businessError string) {
	w.Header().Set(utils.ContentTypeHeaderKey, utils.JSONContentTypeHeader)
	w.WriteHeader(statusCode)
	content, err := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Error:      technicalError,
		Message:    businessError,
	})
	if err != nil {
		return
	}

	//#nosec G104 -- Intended to avoid disruptive code changes
	w.Write(content)
}
