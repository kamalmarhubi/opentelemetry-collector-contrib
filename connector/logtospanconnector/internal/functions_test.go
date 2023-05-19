// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internal // import "github.com/open-telemetry/opentelemetry-collector-contrib/connecctor/logtospanconnector/internal"

import (
	// "context"
	// "testing"
	//
	// "github.com/stretchr/testify/assert"
	// "go.opentelemetry.io/collector/pdata/pcommon"
	// "go.opentelemetry.io/collector/pdata/plog"
	//
	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottllog"
)

// var validSpanID = pcommon.SpanID([8]byte{0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    })
// var validTraceID = pcommon.TraceID([16]byte{0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    })

// func Test_FromLogRecord(t *testing.T) {
// 	t.Skip("skip")
// 	tests := []struct {
// 		name     string
// 		input    func() plog.LogRecord
// 		errorMessage string
// 		expected TraceContext
// 	}{
// 		{
// 			name: "no trace context",
// 			input: func() plog.LogRecord {
// 				return plog.NewLogRecord()
// 			},
// 			expected: TraceContext{},
// 		},
// 		{
// 			name: "missing trace id",
// 			input: func() plog.LogRecord {
// 				lr := plog.NewLogRecord()
// 				lr.SetSpanID(validSpanID)
// 				return lr
// 			},
// 			expected: TraceContext{},
// 		},
// 		{
// 			name: "missing span id",
// 			input: func() plog.LogRecord {
// 				lr := plog.NewLogRecord()
// 				lr.SetTraceID(validTraceID)
// 				return lr
// 			},
// 			errorMessage: "SpanID",
// 			expected: TraceContext{},
// 		},
// 		{
// 			name: "valid",
// 			input: func() plog.LogRecord {
// 				lr := plog.NewLogRecord()
// 				lr.SetSpanID(validSpanID)
// 				lr.SetTraceID(validTraceID)
// 				return lr
// 			},
// 			expected: TraceContext{TraceID: validTraceID, SpanID: validSpanID},
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			exprFunc, err := fromLogRecord()
// 			assert.NoError(t, err)
// 			result, err := exprFunc(context.Background(), ottllog.NewTransformContext(tt.input(), pcommon.NewInstrumentationScope(), pcommon.NewResource()))
// 			assert.NoError(t, err)
// 			assert.Equal(t, tt.expected, result)
// 		})
// 	}
// }
