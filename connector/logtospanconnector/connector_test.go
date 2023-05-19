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

var _ = fuckOff(log.Printf)

type tt struct {
name     string
config   *Config
resource func() pcommon.Resource
scope func() pcommon.InstrumentationScope
logRecord    func() plog.LogRecord
expected func() ptrace.Span
}

func (tt tt) Resource() pcommon.Resource {
		if tt.resource == nil {
				return pcommon.NewResource()
		}
		return tt.resource()
}
func (tt tt) Scope() pcommon.InstrumentationScope {
		if tt.scope == nil {
				return pcommon.NewInstrumentationScope()
		}
		return tt.scope()
}
func Test_convertLogRecord(t *testing.T) {
	tests := []tt{
		{
			name: "empty log with no statements and error_mode unset",
			config: &Config{Statements: []string{
			}},
			logRecord: func() plog.LogRecord {
				return plog.NewLogRecord()
			},
			expected: func() ptrace.Span { return ptrace.NewSpan() },
		},
		{
			name: "empty log with no statements and error_mode ignore",
			config: &Config{Statements: []string{
			}},
			logRecord: func() plog.LogRecord {
				return plog.NewLogRecord()
			},
			expected: func() ptrace.Span { return ptrace.NewSpan() },
		},
		{
			name: "valid trace context",
			config: &Config{Statements: []string{
				`set(name, log.attributes["hi"])`,
				`set(span_id.string, "aabbccddeeff0011")`,
			}},
			// resource: pcommon.NewResource(),
			logRecord: func() plog.LogRecord {
				lr := plog.NewLogRecord()
				lr.SetSpanID(validSpanID)
				lr.SetTraceID(validTraceID)
				lr.Attributes().PutStr("hi", "bye")
				// log.Printf("WTF IS THE BODY: %+v", lr.Body().AsRaw())
				return lr
			},
			expected: func() ptrace.Span {
				span := ptrace.NewSpan()

				span.SetName("bye")
				span.SetSpanID(pcommon.SpanID([8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,    }))

				return span
			},

		},
		{
			name: "set(attributes)",
			config: &Config{Statements: []string{
			`set(attributes, log.attributes)`,
				`set(span_id, log.span_id)`,
				`set(trace_id, log.trace_id)`,
			}},
			// res: pcommon.NewResource(),
			logRecord: func() plog.LogRecord {
				lr := plog.NewLogRecord()
				lr.SetSpanID(validSpanID)
				lr.SetTraceID(validTraceID)
				lr.Attributes().FromRaw(map[string]any{"hi": "bye"})
				// log.Printf("WTF IS THE BODY: %+v", lr.Body().AsRaw())
				return lr
			},
			expected: func() ptrace.Span {
				span := ptrace.NewSpan()

				span.SetSpanID(validSpanID)
				span.SetTraceID(validTraceID)
				span.Attributes().PutStr("hi", "bye")

				return span
			},

		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector, err := newConnector(componenttest.NewNopTelemetrySettings(), tt.config)
			assert.NoError(t, err)

			span, err := connector.convertLogRecord(context.Background(), tt.Resource(), tt.Scope(), tt.logRecord())
			assert.NoError(t, err)
			// fuckOff(log.Printf)
			assert.NoError(t, compareSpan(tt.expected(), span))
			// tc, _, err := connector.traceContextGetter.Execute(context.Background(), ottllog.NewTransformContext(tt.input(), pcommon.NewInstrumentationScope(), pcommon.NewResource()))
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
