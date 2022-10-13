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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/mongoclient"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus"
)

type OPATransport struct {
	http.RoundTripper
	// FIXME: this overlaps with the req.Context used during RoundTrip.
	context                  context.Context
	logger                   *logrus.Entry
	request                  *http.Request
	permission               *RondConfig
	partialResultsEvaluators PartialResultsEvaluators
	env                      config.EnvironmentVariables
}

func is2XX(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

func (t *OPATransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if !is2XX(resp.StatusCode) {
		return resp, nil
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return resp, nil
	}

	if !hasApplicationJSONContentType(resp.Header) {
		t.logger.WithField("foundContentType", resp.Header.Get(ContentTypeHeaderKey)).Debug("found content type")
		t.responseWithError(resp, fmt.Errorf("content-type is not application/json"), http.StatusInternalServerError)
		return resp, nil
	}

	var decodedBody interface{}
	if err := json.Unmarshal(b, &decodedBody); err != nil {
		return nil, fmt.Errorf("response body is not valid: %s", err.Error())
	}

	userInfo, err := mongoclient.RetrieveUserBindingsAndRoles(t.logger, t.request, t.env)
	if err != nil {
		t.responseWithError(resp, err, http.StatusInternalServerError)
		return resp, nil
	}

	input, err := createRegoQueryInput(t.request, t.env, t.permission.Options.EnableResourcePermissionsMapOptimization, userInfo, decodedBody)
	if err != nil {
		t.responseWithError(resp, err, http.StatusInternalServerError)
		return resp, nil
	}

	evaluator, err := t.partialResultsEvaluators.GetEvaluatorFromPolicy(t.context, t.permission.ResponseFlow.PolicyName, input, t.env)
	if err != nil {
		t.logger.WithField("error", logrus.Fields{
			"policyName": t.permission.ResponseFlow.PolicyName,
			"message":    err.Error(),
		}).Error("RBAC policy evaluation on response failed")
		t.responseWithError(resp, err, http.StatusInternalServerError)
		return resp, nil
	}

	bodyToProxy, err := evaluator.evaluate(t.logger)
	if err != nil {
		t.responseWithError(resp, err, http.StatusForbidden)
		return resp, nil
	}

	marshalledBody, err := json.Marshal(bodyToProxy)
	if err != nil {
		t.responseWithError(resp, err, http.StatusInternalServerError)
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
	body := io.NopCloser(bytes.NewReader(newBody))
	originalResponse.Body = body
	originalResponse.ContentLength = int64(len(newBody))
	originalResponse.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
}
