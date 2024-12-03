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

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/custom_builtins"
	"github.com/rond-authz/rond/internal/config"
	"github.com/rond-authz/rond/internal/utils"
	rondlogrus "github.com/rond-authz/rond/logging/logrus"
	"github.com/rond-authz/rond/openapi"
	"github.com/rond-authz/rond/sdk"
	"github.com/rond-authz/rond/types"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestRoundTripErrors(t *testing.T) {
	rondConfig := &core.RondConfig{}
	logger, _ := test.NewNullLogger()

	defer gock.Off()

	t.Run("on unexpected status code from default RoundTrip, proxy error and do nothing", func(t *testing.T) {
		defer gock.Flush()

		responseBody := map[string]interface{}{"answer": float64(42)}
		gock.DisableNetworking()
		gock.New("http://example.com").
			Post("/some-api").
			Reply(http.StatusExpectationFailed). // 417
			JSON(responseBody)

		req := httptest.NewRequest(http.MethodPost, "http://example.com/some-api", nil)
		transport := NewOPATransport(
			http.DefaultTransport,
			req.Context(),
			rondConfig,
			config.EnvironmentVariables{},
			logrus.NewEntry(logger),
			req,
			"",
			core.InputUser{},
			nil,
		)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, http.StatusExpectationFailed, resp.StatusCode, "unexpected status code")

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "unexpected error")

		actualResponseBody := make(map[string]interface{})
		err = json.Unmarshal(bodyBytes, &actualResponseBody)
		require.NoError(t, err, "unexpected error")

		require.Equal(t, responseBody, actualResponseBody)
	})
}

func TestIs2xx(t *testing.T) {
	require.True(t, is2XX(200))
	require.True(t, is2XX(201))
	require.False(t, is2XX(300))
	require.False(t, is2XX(199))
}

func TestOPATransportResponseWithError(t *testing.T) {
	logger, _ := test.NewNullLogger()
	rondConfig := &core.RondConfig{}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/some-api", nil)

	transport := NewOPATransport(
		http.DefaultTransport,
		req.Context(),
		rondConfig,
		config.EnvironmentVariables{},
		logrus.NewEntry(logger),
		req,
		"",
		core.InputUser{},
		nil,
	)

	t.Run("generic business error message", func(t *testing.T) {
		resp := &http.Response{
			Body:          nil,
			ContentLength: 0,
			Header:        http.Header{},
		}

		transport.responseWithError(resp, fmt.Errorf("some error"), http.StatusInternalServerError)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.Nil(t, err)
		expectedBytes, err := json.Marshal(types.RequestError{
			StatusCode: http.StatusInternalServerError,
			Message:    utils.GENERIC_BUSINESS_ERROR_MESSAGE,
			Error:      "some error",
		})
		require.Nil(t, err)
		require.Equal(t, string(expectedBytes), string(bodyBytes))
		require.Equal(t, strconv.Itoa(len(expectedBytes)), resp.Header.Get("content-length"))
	})

	t.Run("permissions error message", func(t *testing.T) {
		resp := &http.Response{
			Body:          nil,
			ContentLength: 0,
			Header:        http.Header{},
		}

		transport.responseWithError(resp, fmt.Errorf("some error"), http.StatusForbidden)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.Nil(t, err)
		expectedBytes, err := json.Marshal(types.RequestError{
			StatusCode: http.StatusForbidden,
			Message:    utils.NO_PERMISSIONS_ERROR_MESSAGE,
			Error:      "some error",
		})
		require.Nil(t, err)
		require.Equal(t, string(expectedBytes), string(bodyBytes))
		require.Equal(t, strconv.Itoa(len(expectedBytes)), resp.Header.Get("content-length"))
	})
}

func TestOPATransportRoundTrip(t *testing.T) {
	rondConfig := &core.RondConfig{}
	logger, _ := test.NewNullLogger()
	req := httptest.NewRequest(http.MethodGet, "/users", nil)

	t.Run("returns error on RoundTrip error", func(t *testing.T) {
		transport := NewOPATransport(
			&MockRoundTrip{Error: fmt.Errorf("some error")},
			req.Context(),
			rondConfig,
			config.EnvironmentVariables{},
			logrus.NewEntry(logger),
			req,
			"",
			core.InputUser{},
			nil,
		)

		_, err := transport.RoundTrip(req)
		require.Error(t, err, "some error")
	})

	t.Run("returns resp on non-2xx response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    http.StatusInternalServerError,
			Body:          io.NopCloser(bytes.NewReader([]byte("original response"))),
			ContentLength: 0,
			Header:        http.Header{},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
			user:         core.InputUser{},
		}

		updatedResp, err := transport.RoundTrip(req)
		require.Nil(t, err)
		bodyBytes, err := io.ReadAll(updatedResp.Body)
		require.Nil(t, err)
		require.Equal(t, "original response", string(bodyBytes))
	})

	t.Run("response read failure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body: &MockReader{
				ReadError: fmt.Errorf("read error"),
			},
			ContentLength: 0,
			Header:        http.Header{},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
			user:         core.InputUser{},
		}

		resp, err := transport.RoundTrip(req)
		require.Nil(t, resp)
		require.Error(t, err, "read error")
	})

	t.Run("response close failure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body: &MockReader{
				ReadError:  io.EOF,
				CloseError: fmt.Errorf("close error"),
			},
			ContentLength: 0,
			Header:        http.Header{},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
			user:         core.InputUser{},
		}

		resp, err := transport.RoundTrip(req)
		require.Nil(t, resp)
		require.Error(t, err, "close error")
	})

	t.Run("response as-is on empty response body", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body: &MockReader{
				ReadError: io.EOF,
			},
			ContentLength: 0,
			Header:        http.Header{http.CanonicalHeaderKey("some"): []string{"content"}},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
			user:         core.InputUser{},
		}

		resp, err := transport.RoundTrip(req)
		require.Nil(t, err)
		require.Equal(t, []string{"content"}, resp.Header[http.CanonicalHeaderKey("some")])
	})

	t.Run("ok with filter response", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte(`{"some":"field"}`))),
			ContentLength: 16,
			Header:        http.Header{"Content-Type": []string{"application/json"}},
		}

		req = req.Clone(context.Background())

		evaluator := getSdk(t, &sdkOptions{
			oasFilePath:      "../mocks/rondOasConfig.json",
			opaModuleContent: "package policies responsepolicy [resources] { resources := input.response.body }",
		})
		evaluatorSDK, err := evaluator.FindEvaluator(http.MethodGet, "/users/")
		require.NoError(t, err)

		transport := NewOPATransport(
			&MockRoundTrip{Response: resp},
			req.Context(),
			rondConfig,
			config.EnvironmentVariables{},
			logrus.NewEntry(logger),
			req,
			// config.EnvironmentVariables{},
			"",
			core.InputUser{},
			evaluatorSDK,
		)

		actualResp, err := transport.RoundTrip(req)
		require.NoError(t, err, "response body is not valid")
		require.Equal(t, http.StatusOK, actualResp.StatusCode)
		require.Equal(t, int64(16), actualResp.ContentLength)

		body, err := io.ReadAll(actualResp.Body)
		require.NoError(t, err)
		require.Equal(t, []byte(`{"some":"field"}`), body)

		expectedHeaders := http.Header{}
		expectedHeaders.Set("Content-Type", "application/json")
		expectedHeaders.Set("Content-Length", "16")

		require.Equal(t, expectedHeaders, actualResp.Header)
	})

	t.Run("failure on non-json response content-type", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte("original response"))),
			ContentLength: 0,
			Header:        http.Header{"Content-Type": []string{"text/plain"}},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
		}

		resp, err := transport.RoundTrip(req)
		require.Nil(t, err)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		bodyBytes, err := io.ReadAll(resp.Body)
		require.Nil(t, err)
		require.Contains(t, string(bodyBytes), "content-type is not application/json")
	})

	t.Run("failure on non-json response even with json content-type", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader([]byte("original response"))),
			ContentLength: 0,
			Header:        http.Header{"Content-Type": []string{"application/json"}},
		}
		transport := &OPATransport{
			RoundTripper: &MockRoundTrip{Response: resp},
			context:      req.Context(),
			logger:       logrus.NewEntry(logger),
			request:      req,
		}

		resp, err := transport.RoundTrip(req)
		require.Nil(t, resp)
		require.Error(t, err, "response body is not valid")
	})
}

type MockRoundTrip struct {
	Error    error
	Response *http.Response
}

func (m *MockRoundTrip) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return m.Response, m.Error
}

type MockReader struct {
	ReadResult int
	ReadError  error
	CloseError error
}

func (m *MockReader) Read(p []byte) (n int, err error) {
	return m.ReadResult, m.ReadError
}

func (m *MockReader) Close() error {
	return m.CloseError
}

type sdkOptions struct {
	opaModuleContent string
	oasFilePath      string

	mongoClient custom_builtins.IMongoClient
}

type tHelper interface {
	Helper()
}

func getSdk(t require.TestingT, options *sdkOptions) sdk.OASEvaluatorFinder {
	if h, ok := t.(tHelper); ok {
		h.Helper()
	}

	logger := rondlogrus.NewLogger(logrus.New())
	if options == nil {
		options = &sdkOptions{}
	}

	var oasFilePath = "../mocks/simplifiedMock.json"
	if options.oasFilePath != "" {
		oasFilePath = options.oasFilePath
	}

	openAPISpec, err := openapi.LoadOASFile(oasFilePath)
	require.NoError(t, err)
	opaModuleContent := `package policies todo { true }`
	if options.opaModuleContent != "" {
		opaModuleContent = options.opaModuleContent
	}
	opaModule := core.MustNewOPAModuleConfig([]core.Module{
		{
			Name:    "example.rego",
			Content: opaModuleContent,
		},
	})

	sdk, err := sdk.NewFromOAS(context.Background(), opaModule, openAPISpec, &sdk.Options{
		EvaluatorOptions: &sdk.EvaluatorOptions{
			MongoClient:           options.mongoClient,
			EnablePrintStatements: true,
		},
		Logger: logger,
	})
	require.NoError(t, err)

	return sdk
}
