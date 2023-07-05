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
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"

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
	mtx.Lock()
	go func() {
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

	mtx.Lock()
	defer mtx.Unlock()
	require.Equal(t, http.ErrServerClosed, listenerError, "Listener server not close correctly")
}

func TestGracefulShutdownServerShutdownFailure(t *testing.T) {
	srv := &MockClosableHTTPServer{
		ShutdownError: fmt.Errorf("shutdown mock error"),
	}
	var mtx sync.Mutex

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGTERM)
	log, hook := test.NewNullLogger()

	mtx.Lock()
	go func(srv *MockClosableHTTPServer) {
		defer mtx.Unlock()
		GracefulShutdown(srv, interruptChan, log, 0)
	}(srv)

	interruptChan <- syscall.SIGTERM

	mtx.Lock()
	defer mtx.Unlock()

	require.Equal(t, 1, srv.ShutdownInvokeTimes)
	require.Equal(t, 1, srv.CloseInvokeTimes)

	require.Equal(t, 1, len(hook.AllEntries()))
	require.Equal(t, "Error during shutdown, forcing close.", hook.AllEntries()[0].Message)
}

func TestGracefulShutdownServerCloseFailure(t *testing.T) {
	srv := &MockClosableHTTPServer{
		ShutdownError: fmt.Errorf("shutdown mock error"),
		CloseError:    fmt.Errorf("close mock error"),
	}
	var mtx sync.Mutex

	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, syscall.SIGTERM)
	log, hook := test.NewNullLogger()

	mtx.Lock()
	go func(srv *MockClosableHTTPServer) {
		defer mtx.Unlock()
		GracefulShutdown(srv, interruptChan, log, 0)
	}(srv)

	interruptChan <- syscall.SIGTERM

	mtx.Lock()
	defer mtx.Unlock()

	require.Equal(t, 1, srv.ShutdownInvokeTimes)
	require.Equal(t, 1, srv.CloseInvokeTimes)

	require.Equal(t, 2, len(hook.AllEntries()))
	require.Equal(t, "Error during shutdown, forcing close.", hook.AllEntries()[0].Message)
	require.Equal(t, "Error during server close.", hook.AllEntries()[1].Message)
}

type MockClosableHTTPServer struct {
	ShutdownError       error
	ShutdownInvokeTimes int
	CloseError          error
	CloseInvokeTimes    int
}

func (m *MockClosableHTTPServer) Shutdown(ctx context.Context) error {
	m.ShutdownInvokeTimes++
	return m.ShutdownError
}

func (m *MockClosableHTTPServer) Close() error {
	m.CloseInvokeTimes++
	return m.CloseError
}
