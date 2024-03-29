// Copyright 2023 Mia srl
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

package rondhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rond-authz/rond/core"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/rond-authz/rond/types"

	"github.com/stretchr/testify/require"
)

func TestRondInput(t *testing.T) {
	config := &core.RondConfig{}
	user := core.InputUser{}
	clientTypeHeaderKey := "clienttypeheader"
	pathParams := map[string]string{}

	t.Run("request body integration", func(t *testing.T) {
		expectedRequestBody := map[string]interface{}{
			"Key": float64(42),
		}
		reqBody := struct{ Key int }{
			Key: 42,
		}
		reqBodyBytes, err := json.Marshal(reqBody)
		require.Nil(t, err, "Unexpected error")

		t.Run("ignored on method GET", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(reqBodyBytes))

			input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})

		t.Run("ignore nil body on method POST", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")

			input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})

		t.Run("added on accepted methods", func(t *testing.T) {
			acceptedMethods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

			for _, method := range acceptedMethods {
				req := httptest.NewRequest(method, "/", bytes.NewReader(reqBodyBytes))
				req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
				input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
				require.NoError(t, err, "Unexpected error")
				require.Equal(t, expectedRequestBody, input.Request.Body)
			}
		})

		t.Run("added with content-type specifying charset", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBodyBytes))
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json;charset=UTF-8")
			input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Equal(t, expectedRequestBody, input.Request.Body)
		})

		t.Run("reject on method POST but with invalid body", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json")
			_, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.ErrorContains(t, err, "failed request body deserialization:")
		})

		t.Run("ignore body on method POST but with another content type", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{notajson}")))
			req.Header.Set(utils.ContentTypeHeaderKey, "multipart/form-data")

			input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})

		t.Run("ignore body with preventBodyLoad", func(t *testing.T) {
			config := &core.RondConfig{
				RequestFlow: core.RequestFlow{
					PreventBodyLoad: true,
				},
			}
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(reqBodyBytes))
			req.Header.Set(utils.ContentTypeHeaderKey, "application/json;charset=UTF-8")

			input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)
			require.NoError(t, err, "Unexpected error")
			require.Nil(t, input.Request.Body)
		})
	})

	t.Run("request userinfo remapping", func(t *testing.T) {
		user := core.InputUser{
			ID:         "UserID",
			Groups:     []string{"UserGroups"},
			Roles:      []types.Role{},
			Bindings:   []types.Binding{},
			Properties: map[string]any{"key": "val"},
		}

		req := httptest.NewRequest(http.MethodGet, "/", bytes.NewReader([]byte{}))

		input, err := NewInput(config, req, clientTypeHeaderKey, pathParams, user, nil)

		require.NoError(t, err, "Unexpected error")
		require.Equal(t, user.ID, input.User.ID)
		require.EqualValues(t, user.Properties, input.User.Properties)
	})
}
