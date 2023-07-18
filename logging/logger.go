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

package logging

import "context"

type Logger interface {
	WithFields(fields map[string]any) Logger
	WithField(field string, value any) Logger

	Error(msg any)
	Warn(msg any)
	Info(msg any)
	Debug(msg any)
	Trace(msg any)
}

type noopLogger struct{}

func (l *noopLogger) WithFields(fields map[string]any) Logger {
	return l
}

func (l *noopLogger) WithField(field string, value any) Logger {
	return l
}

func (l noopLogger) Error(msg any) {}
func (l noopLogger) Info(msg any)  {}
func (l noopLogger) Debug(msg any) {}
func (l noopLogger) Trace(msg any) {}
func (l noopLogger) Warn(msg any)  {}

func NewNoOpLogger() Logger {
	return &noopLogger{}
}

type loggerKey struct{}

func WithContext(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func FromContext(ctx context.Context) Logger {
	logger, ok := ctx.Value(loggerKey{}).(Logger)
	if !ok {
		return &noopLogger{}
	}
	return logger
}
