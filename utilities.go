package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"git.tools.mia-platform.eu/platform/core/rbac-service/types"
)

const ContentTypeHeaderKey = "content-type"
const JSONContentTypeHeader = "application/json"

func hasApplicationJSONContentType(headers http.Header) bool {
	return strings.HasPrefix(headers.Get(ContentTypeHeaderKey), JSONContentTypeHeader)
}

func failResponse(w http.ResponseWriter, technicalError, businessError string) {
	failResponseWithCode(w, http.StatusInternalServerError, technicalError, businessError)
}

func failResponseWithCode(w http.ResponseWriter, statusCode int, technicalError, businessError string) {
	w.WriteHeader(statusCode)
	content, err := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Error:      technicalError,
		Message:    businessError,
	})
	if err != nil {
		return
	}

	w.Header().Set(ContentTypeHeaderKey, JSONContentTypeHeader)
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
