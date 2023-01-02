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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestFailResponseWithCode(t *testing.T) {
	w := httptest.NewRecorder()

	failResponseWithCode(w, http.StatusInternalServerError, "The Error", "The Message")
	require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

	require.Equal(t, utils.JSONContentTypeHeader, w.Result().Header.Get(utils.ContentTypeHeaderKey))

	bodyBytes, err := io.ReadAll(w.Body)
	require.NoError(t, err)

	var response types.RequestError
	err = json.Unmarshal(bodyBytes, &response)
	require.NoError(t, err)

	require.Equal(t, types.RequestError{
		StatusCode: http.StatusInternalServerError,
		Error:      "The Error",
		Message:    "The Message",
	}, response)
}
