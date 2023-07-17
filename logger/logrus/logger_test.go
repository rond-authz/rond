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

package rondlogrus

import (
	"testing"

	"github.com/rond-authz/rond/logger"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestLogrusAdapter(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		logger, hook := getLogger()

		logger.Error("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	})

	t.Run("info", func(t *testing.T) {
		logger, hook := getLogger()

		logger.Info("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	})

	t.Run("debug", func(t *testing.T) {
		logger, hook := getLogger()

		logger.Debug("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
	})

	t.Run("trace", func(t *testing.T) {
		logger, hook := getLogger()

		logger.Trace("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.TraceLevel, hook.LastEntry().Level)
	})

	t.Run("with field", func(t *testing.T) {
		logger, hook := getLogger()

		logger.WithField("some", "value").Info("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		require.Equal(t, logrus.Fields{
			"some": "value",
		}, hook.LastEntry().Data)
	})

	t.Run("with fields", func(t *testing.T) {
		logger, hook := getLogger()

		logger.WithFields(map[string]any{
			"some": "value",
		}).Info("a message")

		require.Len(t, hook.AllEntries(), 1)
		require.Equal(t, "a message", hook.LastEntry().Message)
		require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		require.Equal(t, logrus.Fields{
			"some": "value",
		}, hook.LastEntry().Data)
	})
}

func getLogger() (logger.Logger, *test.Hook) {
	logrusLogger, hook := test.NewNullLogger()
	logrusLogger.SetLevel(logrus.TraceLevel)
	logger := NewLogger(logrusLogger)

	return logger, hook
}
