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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/types"

	"gotest.tools/v3/assert"
)

func TestUnmarshalHeader(t *testing.T) {
	userPropertiesHeaderKey := "miauserproperties"
	mockedUserProperties := map[string]interface{}{
		"my":  "other",
		"key": []string{"is", "not"},
	}
	mockedUserPropertiesStringified, err := json.Marshal(mockedUserProperties)
	assert.NilError(t, err)

	t.Run("header not exists", func(t *testing.T) {
		headers := http.Header{}
		var userProperties map[string]interface{}

		ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)

		assert.Assert(t, !ok, "Unmarshal not existing header")
		assert.NilError(t, err, "Unexpected error if doesn't exist header")
	})

	t.Run("header exists but the unmarshalling fails", func(t *testing.T) {
		headers := http.Header{}
		headers.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
		var userProperties string

		ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)

		assert.Assert(t, !ok, "Unexpected success during unmarshalling")
		assert.ErrorType(t, err, &json.UnmarshalTypeError{}, "Unexpected error on unmarshalling")
	})

	t.Run("header exists and unmarshalling finishes correctly", func(t *testing.T) {
		headers := http.Header{}
		headers.Set(userPropertiesHeaderKey, string(mockedUserPropertiesStringified))
		var userProperties map[string]interface{}

		ok, err := unmarshalHeader(headers, userPropertiesHeaderKey, &userProperties)
		assert.Assert(t, ok, "Unexpected failure")
		assert.NilError(t, err, "Unexpected error")
	})
}

func TestFailResponseWithCode(t *testing.T) {
	w := httptest.NewRecorder()

	failResponseWithCode(w, http.StatusInternalServerError, "The Error", "The Message")
	assert.Equal(t, w.Result().StatusCode, http.StatusInternalServerError)

	assert.Equal(t, w.Result().Header.Get(ContentTypeHeaderKey), JSONContentTypeHeader)

	bodyBytes, err := ioutil.ReadAll(w.Body)
	assert.NilError(t, err)

	var response types.RequestError
	err = json.Unmarshal(bodyBytes, &response)
	assert.NilError(t, err)

	assert.DeepEqual(t, response, types.RequestError{
		StatusCode: http.StatusInternalServerError,
		Error:      "The Error",
		Message:    "The Message",
	})
}
