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

// Package helpers is a set of utilities commonly used by HTTP servers.
package helpers

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// GracefulShutdown waits on notified signal to shutdown until all connections are closed.
func GracefulShutdown(srv *http.Server, interruptChan chan os.Signal, logger *logrus.Logger, delayShutdownSeconds int) {
	// Block until we receive our signal.
	<-interruptChan

	time.Sleep(time.Duration(delayShutdownSeconds) * time.Second)
	if err := srv.Shutdown(context.Background()); err != nil {
		logger.WithError(err).Error("Error during shutdown, forcing close.")
		if err := srv.Close(); err != nil {
			logger.WithError(err).Error("Error during server close.")
		}
	}
}
