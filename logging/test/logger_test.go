/*
 * Copyright 2023 Mia srl
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

package test

import (
	"testing"

	"github.com/rond-authz/rond/logging"

	"github.com/stretchr/testify/require"
)

func TestFakeLogger(t *testing.T) {
	t.Run("no fields", func(t *testing.T) {
		t.Run("info log", func(t *testing.T) {
			logger := GetLogger()

			logger.Info("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  map[string]any{},
				},
			}, records)
		})

		t.Run("trace log", func(t *testing.T) {
			logger := GetLogger()

			logger.Trace("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "trace",
					Message: "my msg",
					Fields:  map[string]any{},
				},
			}, records)
		})

		t.Run("warn log", func(t *testing.T) {
			logger := GetLogger()

			logger.Warn("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "warn",
					Message: "my msg",
					Fields:  map[string]any{},
				},
			}, records)
		})

		t.Run("error log", func(t *testing.T) {
			logger := GetLogger()

			logger.Error("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "error",
					Message: "my msg",
					Fields:  map[string]any{},
				},
			}, records)
		})

		t.Run("debug log", func(t *testing.T) {
			logger := GetLogger()

			logger.Debug("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "debug",
					Message: "my msg",
					Fields:  map[string]any{},
				},
			}, records)
		})

		t.Run("more logs", func(t *testing.T) {
			logger := GetLogger()

			logger.Info("my msg")
			logger.Trace("some other")
			logger.Info("yeah")

			records := getRecords(t, logger)
			require.Len(t, records, 3)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  map[string]any{},
				},
				{
					Level:   "trace",
					Message: "some other",
					Fields:  map[string]any{},
				},
				{
					Level:   "info",
					Message: "yeah",
					Fields:  map[string]any{},
				},
			}, records)
		})
	})

	t.Run("with fields", func(t *testing.T) {
		expectedFields := map[string]any{
			"k1": "v1",
			"k2": "v2",
		}

		t.Run("info log", func(t *testing.T) {
			logger := GetLogger()

			logger.WithFields(expectedFields).Info("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("trace log", func(t *testing.T) {
			logger := GetLogger()

			logger.WithFields(expectedFields).Trace("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "trace",
					Message: "my msg",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("more logs", func(t *testing.T) {
			logger := GetLogger()

			logger.WithFields(expectedFields).Info("my msg")
			logger.WithFields(map[string]any{
				"some": "value",
			}).Trace("some other")
			logger.WithFields(expectedFields).Info("yeah")

			records := getRecords(t, logger)
			require.Len(t, records, 3)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
				{
					Level:   "trace",
					Message: "some other",
					Fields: map[string]any{
						"some": "value",
					},
				},
				{
					Level:   "info",
					Message: "yeah",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("more logs with separate loggers", func(t *testing.T) {
			logger := GetLogger()

			l1 := logger.WithFields(expectedFields)
			l1.Info("my msg")
			l1.WithFields(map[string]any{
				"some": "value",
			}).Trace("some other")

			logger.WithFields(map[string]any{
				"a": "b",
			}).Info("yeah")

			records := getRecords(t, logger)
			require.Len(t, records, 3)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
				{
					Level:   "trace",
					Message: "some other",
					Fields: map[string]any{
						"k1":   "v1",
						"k2":   "v2",
						"some": "value",
					},
				},
				{
					Level:   "info",
					Message: "yeah",
					Fields: map[string]any{
						"a": "b",
					},
				},
			}, records)
		})
	})

	t.Run("with field", func(t *testing.T) {
		expectedFields := map[string]any{
			"k1": "v1",
		}

		t.Run("info log", func(t *testing.T) {
			logger := GetLogger()

			logger.WithField("k1", "v1").Info("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("trace log", func(t *testing.T) {
			logger := GetLogger()

			logger.WithField("k1", "v1").Trace("my msg")

			records := getRecords(t, logger)
			require.Len(t, records, 1)
			require.Equal(t, []Record{
				{
					Level:   "trace",
					Message: "my msg",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("more logs", func(t *testing.T) {
			logger := GetLogger()

			logger.WithField("k1", "v1").Info("my msg")
			logger.WithFields(map[string]any{
				"some": "value",
			}).WithField("a", "b").Trace("some other")
			logger.WithField("k1", "v1").Info("yeah")

			records := getRecords(t, logger)
			require.Len(t, records, 3)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
				{
					Level:   "trace",
					Message: "some other",
					Fields: map[string]any{
						"some": "value",
						"a":    "b",
					},
				},
				{
					Level:   "info",
					Message: "yeah",
					Fields:  expectedFields,
				},
			}, records)
		})

		t.Run("more logs with separate loggers", func(t *testing.T) {
			logger := GetLogger()

			l1 := logger.WithField("k1", "v1")
			l1.Info("my msg")
			l1.WithFields(map[string]any{
				"some": "value",
			}).Trace("some other")

			logger.WithFields(map[string]any{
				"a": "b",
			}).Info("yeah")

			records := getRecords(t, logger)
			require.Len(t, records, 3)
			require.Equal(t, []Record{
				{
					Level:   "info",
					Message: "my msg",
					Fields:  expectedFields,
				},
				{
					Level:   "trace",
					Message: "some other",
					Fields: map[string]any{
						"k1":   "v1",
						"some": "value",
					},
				},
				{
					Level:   "info",
					Message: "yeah",
					Fields: map[string]any{
						"a": "b",
					},
				},
			}, records)
		})
	})

	t.Run("get records fails", func(t *testing.T) {
		_, err := GetRecords(nil)
		require.EqualError(t, err, "cannot get test logger")
	})
}

func getRecords(t *testing.T, log logging.Logger) []Record {
	records, err := GetRecords(log)
	require.NoError(t, err)
	return records
}
