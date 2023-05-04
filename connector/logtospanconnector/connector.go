// Copyright The OpenTelemetry Authors
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

package logtospanconnector // import "github.com/open-telemetry/opentelemetry-collector-contrib/connector/logtospanconnector"

import (
	// "bytes"
	"context"
	"log"
	"sync"
	// "time"

	// "github.com/lightstep/go-expohisto/structure"
	// "github.com/tilinna/clock"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	// conventions "go.opentelemetry.io/collector/semconv/v1.6.1"
	"go.uber.org/zap"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottllog"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/logtospanconnector/internal"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector/internal/cache"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector/internal/metrics"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/traceutil"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil"
)

func init() {
	fuckOff(log.Printf)
}

func fuckOff(_ any) {}


type logtospan struct {
	lock   sync.Mutex
	settings component.TelemetrySettings
	
	config Config

	logsConsumer consumer.Logs
	traceContextGetter *ottl.Statement[ottllog.TransformContext]
	spanNameGetter *ottl.Statement[ottllog.TransformContext]

	done    chan struct{}
	started bool

	shutdownOnce sync.Once
}

func parseWithFunctions(settings component.TelemetrySettings, factoryMap internal.FactoryMap, stmt string) (*ottl.Statement[ottllog.TransformContext], error) {
	parser, err :=  ottllog.NewParser(factoryMap, settings)
	if err != nil {
		return nil, err
	}
	parsed, err := parser.ParseStatement(stmt)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func newConnector(settings component.TelemetrySettings, config component.Config) (*logtospan, error) {
	settings.Logger.Info("Building logtospan connector")
	cfg := config.(*Config)

	traceContextGetter, err := parseWithFunctions(settings, internal.TraceContextFunctions(), cfg.TraceContext)
	if err != nil {
		return nil, err
	}

	spanNameGetter, err := parseWithFunctions(settings, internal.TraceContextFunctions(), cfg.SpanName)
	if err != nil {
		return nil, err
	}

	return &logtospan{
		settings: settings, 
		config:                *cfg,
		traceContextGetter: traceContextGetter,
		spanNameGetter: spanNameGetter,
		done:                  make(chan struct{}),
	}, nil
}


// Start implements the component.Component interface.
func (c *logtospan) Start(ctx context.Context, _ component.Host) error {
	c.settings.Logger.Info("Starting logtospan connector")

	c.started = true
	go func() {
		for {
			select {
			case <-c.done:
				return
			}
		}
	}()

	return nil
}

// Shutdown implements the component.Component interface.
func (c *logtospan) Shutdown(context.Context) error {
	c.shutdownOnce.Do(func() {
		c.settings.Logger.Info("Shutting down logtospan connector")
		if c.started {
			c.started = false
		}
	})
	return nil
}

// Capabilities implements the consumer interface.
func (c *logtospan) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces implements the consumer.Traces interface.
// It aggregates the trace data to generate metrics.
func (c *logtospan) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.convertLogs(ctx, logs)
	return nil
}

func (c *logtospan) convertLogRecord(ctx context.Context, res pcommon.Resource, scope pcommon.InstrumentationScope, lr plog.LogRecord) (ptrace.Span, error) {
	span := ptrace.NewSpan()

	tcRes, _, err := c.traceContextGetter.Execute(ctx, ottllog.NewTransformContext(lr, scope, res))
	if err != nil {
		return span, err
	}
	tc := tcRes.(internal.TraceContext)
	// if !tc.IsValid() {
	// 	continue
	// }

	nameRes, _, err := c.spanNameGetter.Execute(ctx, ottllog.NewTransformContext(lr, scope, res))
	if err != nil {
		c.settings.Logger.Info("lol", zap.Any("ahahah", nameRes))
		return span, err
	}
	missingno := "missingno"
	name := nameRes.(*string)
	if name == nil {
		name = &missingno
	}

	span.SetName(*name)
	span.SetTraceID(tc.TraceID)
	span.SetSpanID(tc.SpanID)
	span.SetParentSpanID(tc.ParentSpanID)

	return span, nil
}

func (c *logtospan) convertLogs(ctx context.Context, logs plog.Logs) (ptrace.Traces, error) {
	traces := ptrace.NewTraces()
	rss := traces.ResourceSpans()

	rlogss := logs.ResourceLogs()
	for i := 0; i < rlogss.Len(); i++ {
		rlogs := rlogss.At(i)
		res := rlogs.Resource()

		rspans := rss.AppendEmpty()
		res.CopyTo(rspans.Resource())

		slogss := rlogs.ScopeLogs()
		sspanss := rspans.ScopeSpans()
		for j := 0; j < slogss.Len(); j++ {
			slogs := slogss.At(j)
			scope := slogs.Scope()

			sspans := sspanss.AppendEmpty()
			scope.CopyTo(sspans.Scope())

			lrs := slogs.LogRecords()
			spans := sspans.Spans()
			for k := 0; k < lrs.Len(); k++ {
				lr := lrs.At(k)

				if lr.Body().Type() != pcommon.ValueTypeStr {
					// TODO
					// log? metric?
				}

				tcRes, _, err := c.traceContextGetter.Execute(ctx, ottllog.NewTransformContext(lr, scope, res))
				if err != nil {
					return traces, err
				}
				tc := tcRes.(internal.TraceContext)
				if !tc.IsValid() {
					continue
				}
				nameRes, _, err := c.spanNameGetter.Execute(ctx, ottllog.NewTransformContext(lr, scope, res))
				if err != nil {
					c.settings.Logger.Info("lol", zap.Any("ahahah", nameRes))
					return traces, err
				}
				name := *nameRes.(*string)
				c.settings.Logger.Info("lol", zap.Any("ahahah", name))

				span := spans.AppendEmpty()
				span.SetName(*nameRes.(*string))
				span.SetTraceID(tc.TraceID)
				span.SetSpanID(tc.SpanID)
				span.SetParentSpanID(tc.ParentSpanID)
				if err != nil {
					return traces, err
				}
			}
		}
	}
	return traces, nil
}
