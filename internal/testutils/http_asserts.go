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

package testutils

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func AssertResponseError(t *testing.T, resp *httptest.ResponseRecorder, statusCode int, technicalErrMsg string) {
	AssertResponseFullErrorMessages(t, resp, statusCode, technicalErrMsg, "")
}

func AssertResponseFullErrorMessages(t *testing.T, resp *httptest.ResponseRecorder, statusCode int, technicalErrMsg, businessErrMsg string) {
	t.Helper()
	respBodyBuff, err := io.ReadAll(resp.Body)
	defer resp.Result().Body.Close()

	require.NoError(t, err, "Unexpected error in the response body")

	var respBody types.RequestError
	err = json.Unmarshal(respBodyBuff, &respBody)
	require.NoError(t, err, "Unexpected error during unmarshalling of the response body")

	require.Equal(t, statusCode, respBody.StatusCode, "Unexpected status code")

	if technicalErrMsg != "" {
		require.Equal(t, technicalErrMsg, respBody.Error, "Unexpected technical error message")
	}

	if businessErrMsg != "" {
		require.Equal(t, businessErrMsg, respBody.Message, "Unexpected technical error message")
	}
}
