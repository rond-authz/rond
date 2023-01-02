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
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mia-platform/glogger/v2"
	"github.com/rond-authz/rond/internal/utils"
	"github.com/sirupsen/logrus"
)

// StatusResponse type.
type StatusResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func handleStatusRoutes(w http.ResponseWriter, serviceName, serviceVersion string) (*StatusResponse, []byte) {
	w.Header().Add(utils.ContentTypeHeaderKey, utils.JSONContentTypeHeader)
	status := StatusResponse{
		Status:  "OK",
		Name:    serviceName,
		Version: serviceVersion,
	}
	body, err := json.Marshal(&status)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil, nil
	}

	return &status, body
}

var statusRoutes = []string{"/-/rbac-healthz", "/-/rbac-ready", "/-/rbac-check-up"}

func handleStatusEndpoint(serviceName, serviceVersion string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		_, body := handleStatusRoutes(w, serviceName, serviceVersion)
		if _, err := w.Write(body); err != nil {
			logger := glogger.Get(req.Context())
			logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
		}
	}
}

// StatusRoutes add status routes to router.
func StatusRoutes(r *mux.Router, serviceName, serviceVersion string) {
	statusEndpointHandler := handleStatusEndpoint(serviceName, serviceVersion)
	r.HandleFunc("/-/rbac-healthz", statusEndpointHandler)

	r.HandleFunc("/-/rbac-ready", statusEndpointHandler)

	r.HandleFunc("/-/rbac-check-up", statusEndpointHandler)
}
