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

package helpers

import (
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sirupsen/logrus/hooks/test"
)

func TestGracefulShutdown(t *testing.T) {
	srv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}

	var mtx sync.Mutex
	var listenerError error
	go func() {
		mtx.Lock()
		defer mtx.Unlock()

		listenerError = srv.ListenAndServe()
	}()

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGTERM)
	log, _ := test.NewNullLogger()

	go func() {
		GracefulShutdown(srv, interruptChan, log, 0)
	}()

	interruptChan <- syscall.SIGTERM

	time.Sleep(500 * time.Millisecond)

	mtx.Lock()
	defer mtx.Unlock()
	require.Equal(t, http.ErrServerClosed, listenerError, "Listener server not close correctly")
}
