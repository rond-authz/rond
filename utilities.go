package main

import (
	"encoding/json"
	"net/http"

	"rbac-service/internal/types"
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
