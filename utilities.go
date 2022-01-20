package main

import (
	"encoding/json"
	"net/http"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"
)

func failResponse(w http.ResponseWriter, message string) {
	failResponseWithCode(w, http.StatusInternalServerError, message)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	content, err := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Message:    message,
	})
	if err != nil {
		return
	}
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
