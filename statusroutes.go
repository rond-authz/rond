/*
 * Copyright 2019 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

// StatusResponse type.
type StatusResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func handleStatusRoutes(w http.ResponseWriter, serviceName, serviceVersion string) (*StatusResponse, []byte) {
	w.Header().Add("Content-Type", "application/json")
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

// StatusRoutes add status routes to router.
func StatusRoutes(r *mux.Router, serviceName, serviceVersion string) {
	r.HandleFunc("/-/rbac-healthz", func(w http.ResponseWriter, req *http.Request) {
		_, body := handleStatusRoutes(w, serviceName, serviceVersion)
		w.Write(body)
	})

	r.HandleFunc("/-/rbac-ready", func(w http.ResponseWriter, req *http.Request) {
		_, body := handleStatusRoutes(w, serviceName, serviceVersion)
		w.Write(body)
	})

	r.HandleFunc("/-/rbac-check-up", func(w http.ResponseWriter, req *http.Request) {
		_, body := handleStatusRoutes(w, serviceName, serviceVersion)
		w.Write(body)
	})
}
