package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"gotest.tools/assert"
)

func TestUtilities(t *testing.T) {
	t.Run("TestUnmarshalHeader", func(t *testing.T) {
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
	})
}
