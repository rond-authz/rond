package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/config"
	"git.tools.mia-platform.eu/platform/core/rbac-service/internal/types"

	"github.com/sirupsen/logrus"
)

type OPATransport struct {
	http.RoundTripper
	logger     *logrus.Entry
	request    *http.Request
	env        config.EnvironmentVariables
	permission *XPermission
}

func (t *OPATransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return resp, nil
	}

	if !hasApplicationJSONContentType(resp.Header) {
		t.logger.WithField("foundContentType", resp.Header.Get("content-type")).Debug("found content type")
		t.responseWithError(resp, fmt.Errorf("Content-type is not application/json"), http.StatusInternalServerError)
		return resp, nil
	}

	var decodedBody interface{}
	if err := json.Unmarshal(b, &decodedBody); err != nil {
		return nil, fmt.Errorf("response body is not valid: %s", err.Error())
	}

	evaluator, err := createEvaluator(
		t.logger,
		t.request,
		t.env,
		t.permission.ResponseFilter.Policy,
		decodedBody,
	)
	if err != nil {
		t.responseWithError(resp, err, http.StatusInternalServerError)
		return resp, nil
	}

	bodyToProxy, _, err := evaluator.PolicyEvaluation(t.logger, t.permission)
	if err != nil {
		t.responseWithError(resp, err, http.StatusForbidden)
		return resp, nil
	}
	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		t.responseWithError(resp, err, http.StatusForbidden)
		return resp, nil
	}
	overwriteResponse(resp, marshalledBody)
	return resp, nil
}

func (t *OPATransport) responseWithError(resp *http.Response, err error, statusCode int) {
	t.logger.WithField("error", logrus.Fields{"message": err.Error()}).Error("error while evaluating column filter query")
	message := NO_PERMISSIONS_ERROR_MESSAGE
	if statusCode != http.StatusForbidden {
		message = GENERIC_BUSINESS_ERROR_MESSAGE
	}
	content, _ := json.Marshal(types.RequestError{
		StatusCode: statusCode,
		Message:    message,
		Error:      err.Error(),
	})
	overwriteResponseWithStatusCode(resp, content, statusCode)
}

func overwriteResponseWithStatusCode(originalResponse *http.Response, newBody []byte, statusCode int) {
	overwriteResponse(originalResponse, newBody)
	originalResponse.StatusCode = statusCode
}

func overwriteResponse(originalResponse *http.Response, newBody []byte) {
	body := ioutil.NopCloser(bytes.NewReader(newBody))
	originalResponse.Body = body
	originalResponse.ContentLength = int64(len(newBody))
	originalResponse.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
}
