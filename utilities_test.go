package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"git.tools.mia-platform.eu/platform/core/rbac-service/types"

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
	assert.Equal(t, w.Code, http.StatusInternalServerError)

	assert.Equal(t, w.Header().Get(ContentTypeHeaderKey), "application/json")

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
