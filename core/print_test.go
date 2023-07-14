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

package core

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/open-policy-agent/opa/topdown/print"
	"github.com/stretchr/testify/require"
)

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrintHook(&buf, "policy-name")

	err := h.Print(print.Context{}, "the print message")
	require.NoError(t, err)

	var re = regexp.MustCompile(`"time":\d+`)
	require.JSONEq(t, `{"level":10,"msg":"the print message","time":123,"policyName":"policy-name"}`, string(re.ReplaceAll(buf.Bytes(), []byte("\"time\":123"))))
}
