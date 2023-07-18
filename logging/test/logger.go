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
	"fmt"
	"sync"

	"github.com/rond-authz/rond/logging"
)

type Record struct {
	Fields  map[string]any
	Message string
	Level   string
}

type entry struct {
	testLogger
	records        []Record
	originalLogger *testLogger
}

type testLogger struct {
	mu     sync.RWMutex
	Fields map[string]any
	entry  *entry
}

func (l *testLogger) setRecord(level string, msg any) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	l.entry.records = append(l.entry.records, Record{
		Fields:  l.Fields,
		Message: fmt.Sprint(msg),
		Level:   level,
	})

	if originalLogger := l.entry.originalLogger; originalLogger != nil {
		originalLogger.mu.RLock()
		defer originalLogger.mu.RUnlock()

		originalLogger.entry.records = append(originalLogger.entry.records, Record{
			Fields:  l.Fields,
			Message: fmt.Sprint(msg),
			Level:   level,
		})
	}
}

func (l *testLogger) Warn(msg any) {
	l.setRecord("warn", msg)
}

func (l *testLogger) Error(msg any) {
	l.setRecord("error", msg)
}

func (l *testLogger) Debug(msg any) {
	l.setRecord("debug", msg)
}

func (l *testLogger) Info(msg any) {
	l.setRecord("info", msg)
}

func (l *testLogger) Trace(msg any) {
	l.setRecord("trace", msg)
}

func (l *testLogger) WithFields(fields map[string]any) logging.Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	clonedFields := map[string]any{}
	for k, v := range l.Fields {
		clonedFields[k] = v
	}

	originalLogger := l
	if l.entry.originalLogger != nil {
		originalLogger = l.entry.originalLogger
	}

	logger := &testLogger{
		Fields: clonedFields,
		entry: &entry{
			testLogger: testLogger{
				Fields: clonedFields,
				entry:  l.entry,
			},
			originalLogger: originalLogger,
			records:        l.entry.records,
		},
	}
	for k, v := range fields {
		logger.entry.Fields[k] = v
	}
	return logger
}

func (l *testLogger) WithField(key string, value any) logging.Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	clonedFields := map[string]any{}
	for k, v := range l.Fields {
		clonedFields[k] = v
	}

	originalLogger := l
	if l.entry.originalLogger != nil {
		originalLogger = l.entry.originalLogger
	}

	logger := &testLogger{
		Fields: clonedFields,
		entry: &entry{
			testLogger: testLogger{
				Fields: clonedFields,
				entry:  l.entry,
			},
			originalLogger: originalLogger,
			records:        l.entry.records,
		},
	}
	logger.entry.Fields[key] = value
	return logger
}

func (e *entry) AllRecords() []Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.records
}

func (l *testLogger) OriginalLogger() *entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entry
}

func GetLogger() logging.Logger {
	return &testLogger{
		Fields: map[string]any{},
		entry: &entry{
			records: []Record{},
		},
	}
}

func GetRecords(log logging.Logger) ([]Record, error) {
	testLog, ok := log.(*testLogger)
	if ok {
		return testLog.OriginalLogger().AllRecords(), nil
	}
	return nil, fmt.Errorf("cannot get test logger")
}
