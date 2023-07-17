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
	"github.com/rond-authz/rond/logger"

	"github.com/sirupsen/logrus"
)

type logrusEntryWrapper struct {
	*logrus.Entry
}

func (l *logrusEntryWrapper) WithField(key string, value any) logger.Logger {
	entry := l.Logger.WithField(key, value)
	return &logrusEntryWrapper{entry}
}

func (l *logrusEntryWrapper) WithFields(fields map[string]any) logger.Logger {
	entry := l.Logger.WithFields(fields)
	return &logrusEntryWrapper{entry}
}

func (l logrusEntryWrapper) Info(msg any) {
	l.Entry.Info(msg)
}

func (l logrusEntryWrapper) Trace(msg any) {
	l.Entry.Trace(msg)
}

func (l logrusEntryWrapper) Debug(msg any) {
	l.Entry.Debug(msg)
}

func (l logrusEntryWrapper) Error(msg any) {
	l.Entry.Error(msg)
}

func (l logrusEntryWrapper) Warn(msg any) {
	l.Entry.Warn(msg)
}

func NewLogger(logger *logrus.Logger) logger.Logger {
	return &logrusEntryWrapper{logrus.NewEntry(logger)}
}

func NewEntry(entry *logrus.Entry) logger.Logger {
	return &logrusEntryWrapper{entry}
}
