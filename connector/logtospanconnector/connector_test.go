package logtospanconnector

import (
	"testing"
	"log"
	"context"
	"github.com/google/go-cmp/cmp"
	// "github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"fmt"

	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottllog"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/plog"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/connector/logtospanconnector/internal"
	"go.opentelemetry.io/collector/component/componenttest"
)
var validSpanID = pcommon.SpanID([8]byte{0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    })
var validTraceID = pcommon.TraceID([16]byte{0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba,    })

func Test_convertLogRecord(t *testing.T) {
	t.Fail()
	tests := []struct {
		name     string
		config   *Config
		res pcommon.Resource
		scope pcommon.InstrumentationScope
		input    func() plog.LogRecord
		expected func() ptrace.Span
	}{
		{
			name: "no logs",
			config: &Config{TraceContext: "from_log_record()", SpanName: "from(body)"},
			input: func() plog.LogRecord {
				return plog.NewLogRecord()
			},
			expected: func() ptrace.Span { return ptrace.NewSpan() },
		},
		{
			name: "valid trace context",
			config: &Config{TraceContext: "from_log_record()", SpanName: "from(body)"},
			res: pcommon.NewResource(),
			input: func() plog.LogRecord {
				lr := plog.NewLogRecord()
				lr.SetSpanID(validSpanID)
				lr.SetTraceID(validTraceID)
				lr.Body().SetEmptyMap().PutStr("WTTTT", "Abdk")
				return lr
			},
			expected: func() ptrace.Span {
				span := ptrace.NewSpan()

				span.SetName("wtf")

				return span
			},

		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector, err := newConnector(componenttest.NewNopTelemetrySettings(), tt.config)
			assert.NoError(t, err)

			span, err := connector.convertLogRecord(context.Background(), tt.res, tt.scope, tt.input())
			fuckOff(log.Printf)
			assert.NoError(t, compareSpan(tt.expected(), span))
			// tc, _, err := connector.traceContextGetter.Execute(context.Background(), ottllog.NewTransformContext(tt.input(), pcommon.NewInstrumentationScope(), pcommon.NewResource()))
			assert.NoError(t, err)
			// assert.Equal(t, tt.expected, tc)
		})
	}
}

func compareSpan(expected, actual ptrace.Span) error {
	return multierr.Combine(
		compare("Span.Name", expected.Name(), actual.Name()),
		compare("Span.TraceID", expected.TraceID(), actual.TraceID()),
		compare("Span.SpanID", expected.SpanID(), actual.SpanID()),
		compare("Span.ParentSpanID", expected.ParentSpanID(), actual.ParentSpanID()),
		compare("Span.StartTimestamp", expected.StartTimestamp(), actual.StartTimestamp()),
		compare("Span.EndTimestamp", expected.EndTimestamp(), actual.EndTimestamp()),
		compare("Span.Attributes", expected.Attributes().AsRaw(), actual.Attributes().AsRaw()),
		// compare("Span.Status", expected.Status(), actual.Status()),
	)
}

func compare(ty string, expected, actual any, opts ...cmp.Option) error {
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		return fmt.Errorf("%s mismatch (-expected +actual):\n%s", ty, diff)
	}
	return nil
}
