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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"gopkg.in/h2non/gock.v1"
	"gotest.tools/v3/assert"
)

func TestRoundTripErrors(t *testing.T) {
	logger, _ := test.NewNullLogger()
	envs := config.EnvironmentVariables{}

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
		transport := &OPATransport{
			http.DefaultTransport,
			req.Context(),
			logrus.NewEntry(logger),
			req,
			nil,
			nil,
			envs,
		}

		resp, err := transport.RoundTrip(req)
		assert.NilError(t, err, "unexpected error")
		assert.Equal(t, resp.StatusCode, http.StatusExpectationFailed, "unexpected status code")

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		assert.NilError(t, err, "unexpected error")

		actualResponseBody := make(map[string]interface{})
		err = json.Unmarshal(bodyBytes, &actualResponseBody)
		assert.NilError(t, err, "unexpected error")

		assert.DeepEqual(t, responseBody, actualResponseBody)
	})
}
