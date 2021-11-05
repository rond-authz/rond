package main

import (
	"encoding/json"
	"net/http"
)

type RequestError struct {
	Error      string `json:"error"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

func failResponse(w http.ResponseWriter, message string) {
	failResponseWithCode(w, http.StatusInternalServerError, message)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	content, err := json.Marshal(RequestError{
		StatusCode: statusCode,
		Message:    message,
	})
	if err != nil {
		return
	}
	w.Write(content)
}
