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
	"encoding/json"
	"net/http"

	"github.com/rond-authz/rond/internal/utils"

	"github.com/gorilla/mux"
	glogrus "github.com/mia-platform/glogger/v4/loggers/logrus"
	"github.com/sirupsen/logrus"
)

var statusRoutes = []string{"/-/rbac-healthz", "/-/rbac-ready", "/-/rbac-check-up"}

// StatusResponse type.
type StatusResponse struct {
	Status  string `json:"status"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func sendStatusRoutes(w http.ResponseWriter, logger *logrus.Entry, ok bool, serviceName, serviceVersion string) {
	statusMessage := "OK"
	statusCode := http.StatusOK
	if !ok {
		statusMessage = "KO"
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Add(utils.ContentTypeHeaderKey, utils.JSONContentTypeHeader)
	status := StatusResponse{
		Status:  statusMessage,
		Name:    serviceName,
		Version: serviceVersion,
	}
	body, err := json.Marshal(&status)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(statusCode)
	if _, err := w.Write(body); err != nil {
		logger.WithField("error", logrus.Fields{"message": err.Error()}).Warn("failed response write")
	}
}

func handleOKHandler(serviceName, serviceVersion string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		sendStatusRoutes(
			w,
			glogrus.FromContext(req.Context()),
			true,
			serviceName,
			serviceVersion,
		)
	}
}

func handleSDKReadyHandler(sdkBoot *SDKBootState, serviceName, serviceVersion string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		sdkReady := false
		if sdkBoot.IsReady() {
			sdkReady = true
		}

		sendStatusRoutes(
			w,
			glogrus.FromContext(req.Context()),
			sdkReady,
			serviceName,
			serviceVersion,
		)
	}
}

// StatusRoutes add status routes to router.
func StatusRoutes(r *mux.Router, sdkBoot *SDKBootState, serviceName, serviceVersion string) {
	sdkReadyHandler := handleSDKReadyHandler(sdkBoot, serviceName, serviceVersion)
	alwaysOKHandler := handleOKHandler(serviceName, serviceVersion)

	r.HandleFunc("/-/rbac-healthz", alwaysOKHandler)

	r.HandleFunc("/-/rbac-ready", sdkReadyHandler)

	r.HandleFunc("/-/rbac-check-up", alwaysOKHandler)
}
