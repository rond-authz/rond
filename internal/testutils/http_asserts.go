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
