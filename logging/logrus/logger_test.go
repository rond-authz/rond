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

	"github.com/rond-authz/rond/logging"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestLogrusAdapter(t *testing.T) {
	testCases := []struct {
		name          string
		test          func(t *testing.T, log logging.Logger)
		expectedMsg   string
		expectedLevel logrus.Level
		expectedData  logrus.Fields
	}{
		{
			name: "error",
			test: func(t *testing.T, log logging.Logger) {
				log.Error("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.ErrorLevel,
		},
		{
			name: "warn",
			test: func(t *testing.T, log logging.Logger) {
				log.Warn("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.WarnLevel,
		},
		{
			name: "info",
			test: func(t *testing.T, log logging.Logger) {
				log.Info("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.InfoLevel,
		},
		{
			name: "debug",
			test: func(t *testing.T, log logging.Logger) {
				log.Debug("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.DebugLevel,
		},
		{
			name: "trace",
			test: func(t *testing.T, log logging.Logger) {
				log.Trace("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.TraceLevel,
		},
		{
			name: "with fields",
			test: func(t *testing.T, log logging.Logger) {
				log.WithFields(map[string]any{
					"some": "value",
				}).Info("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.InfoLevel,
			expectedData: logrus.Fields{
				"some": "value",
			},
		},
		{
			name: "with field",
			test: func(t *testing.T, log logging.Logger) {
				log.WithField("some", "value").Info("a message")
			},
			expectedMsg:   "a message",
			expectedLevel: logrus.InfoLevel,
			expectedData: logrus.Fields{
				"some": "value",
			},
		},
	}

	t.Run("from logger", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				logrusLogger, hook := test.NewNullLogger()
				logrusLogger.SetLevel(logrus.TraceLevel)
				logger := NewLogger(logrusLogger)

				testCase.test(t, logger)
				require.Len(t, hook.AllEntries(), 1)
				require.Equal(t, testCase.expectedMsg, hook.LastEntry().Message)
				require.Equal(t, testCase.expectedLevel, hook.LastEntry().Level)
				if testCase.expectedData != nil {
					require.Equal(t, testCase.expectedData, hook.LastEntry().Data)
				}
			})
		}
	})

	t.Run("from entry", func(t *testing.T) {
		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				logrusLogger, hook := test.NewNullLogger()
				logrusLogger.SetLevel(logrus.TraceLevel)
				entry := logrus.NewEntry(logrusLogger)
				logger := NewEntry(entry)

				testCase.test(t, logger)
				require.Len(t, hook.AllEntries(), 1)
				require.Equal(t, testCase.expectedMsg, hook.LastEntry().Message)
				require.Equal(t, testCase.expectedLevel, hook.LastEntry().Level)
				if testCase.expectedData != nil {
					require.Equal(t, testCase.expectedData, hook.LastEntry().Data)
				}
			})
		}
	})
}
