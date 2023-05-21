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
	"fmt"
	// "time"
	"reflect"

	// "github.com/lightstep/go-expohisto/structure"
	// "github.com/tilinna/clock"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	// conventions "go.opentelemetry.io/collector/semconv/v1.6.1"
	// "go.uber.org/zap"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/logtospan"

	"github.com/open-telemetry/opentelemetry-collector-contrib/connector/logtospanconnector/internal"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector/internal/cache"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector/internal/metrics"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal/traceutil"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil"
)
type empty struct{}

func init() {
	fuckOff(log.Printf)
	// fuckOff(zap.Any)
	packageName := reflect.TypeOf(empty{}).PkgPath()
	fmt.Println("Current package name:", packageName)

	// Alternatively, you can use the runtime package:
	packageName = reflect.TypeOf(struct{}{}).PkgPath()
	fmt.Println("Current package name (using runtime):", packageName)
}

func fuckOff(_ any) any { return nil }

type connector struct {
	lock     sync.Mutex
	settings component.TelemetrySettings

	config Config

	logsConsumer consumer.Logs
	// just have some defaults
	// trace context: get from log
	// parent: need to specify
	//
	// traceContextGetter *ottl.Statement[ottllog.TransformContext]
	// spanNameGetter *ottl.Statement[ottllog.TransformContext]
	statements ottl.Statements[logtospan.TransformContext]

	done    chan struct{}
	started bool

	shutdownOnce sync.Once
}

func parseWithFunctions(settings component.TelemetrySettings, factoryMap internal.FactoryMap, stmts []string) ([]*ottl.Statement[logtospan.TransformContext], error) {
	parser, err := logtospan.NewParser(factoryMap, settings)
	if err != nil {
		return nil, err
	}
	parsed, err := parser.ParseStatements(stmts)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func newConnector(settings component.TelemetrySettings, config component.Config) (*connector, error) {
	settings.Logger.Info("Building logtospan connector")
	cfg := config.(*Config)

	statements, err := parseWithFunctions(settings, internal.TraceContextFunctions(), cfg.Statements)
	if err != nil {
		return nil, err
	}

	return &connector{
		settings:   settings,
		config:     *cfg,
		statements: ottl.NewStatements(statements, settings, ottl.WithErrorMode[logtospan.TransformContext](cfg.ErrorMode)),
		done:       make(chan struct{}),
	}, nil
}

// Start implements the component.Component interface.
func (c *connector) Start(ctx context.Context, _ component.Host) error {
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
func (c *connector) Shutdown(context.Context) error {
	c.shutdownOnce.Do(func() {
		c.settings.Logger.Info("Shutting down logtospan connector")
		if c.started {
			c.started = false
		}
	})
	return nil
}

// Capabilities implements the consumer interface.
func (c *connector) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeTraces implements the consumer.Traces interface.
// It aggregates the trace data to generate metrics.
func (c *connector) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.convertLogs(ctx, logs)
	return nil
}

func (c *connector) convertLogRecord(ctx context.Context, res pcommon.Resource, scope pcommon.InstrumentationScope, lr plog.LogRecord) (ptrace.Span, error) {
	span := ptrace.NewSpan()

	// log.Printf("%+v", c.statements)
	err := c.statements.Execute(ctx, logtospan.NewTransformContext(res, scope, lr, span))

	return span, err
}

// func (c *connector) convertLogRecord(ctx context.Context, res pcommon.Resource, scope pcommon.InstrumentationScope, lr plog.LogRecord) (ptrace.Span, error) {
// 	span := ptrace.NewSpan()
//
// 	tcRes, _, err := c.traceContextGetter.Execute(ctx, logtospan.NewTransformContext(lr, scope, res))
// 	if err != nil {
// 		return span, err
// 	}
// 	tc := tcRes.(internal.TraceContext)
// 	// if !tc.IsValid() {
// 	// 	continue
// 	// }
//
// 	nameRes, _, err := c.spanNameGetter.Execute(ctx, logtospan.NewTransformContext(lr, scope, res))
// 	if err != nil {
// 		c.settings.Logger.Info("lol", zap.Any("ahahah", nameRes))
// 		return span, err
// 	}
// 	missingno := "missingno"
// 	name := nameRes.(*string)
// 	if name == nil {
// 		name = &missingno
// 	}
//
// 	span.SetName(*name)
// 	span.SetTraceID(tc.TraceID)
// 	span.SetSpanID(tc.SpanID)
// 	span.SetParentSpanID(tc.ParentSpanID)
//
// 	return span, nil
// }

func (c *connector) convertLogs(ctx context.Context, logs plog.Logs) (ptrace.Traces, error) {
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
					c.settings.Logger.Info("log with non-string body")
					// TODO
					// log? metric?
				}

				span, err := c.convertLogRecord(ctx, res, scope, lr)
				if err != nil {
					// TODO something?
					return traces, err
				}

				span.MoveTo(spans.AppendEmpty())
				//
				//
				// tc := tcRes.(internal.TraceContext)
				// if !tc.IsValid() {
				// 	continue
				// }
				// nameRes, _, err := c.spanNameGetter.Execute(ctx, logtospan.NewTransformContext(lr, scope))
				// if err != nil {
				// 	c.settings.Logger.Info("lol", zap.Any("ahahah", nameRes))
				// 	return traces, err
				// }
				// name := *nameRes.(*string)
				// c.settings.Logger.Info("lol", zap.Any("ahahah", name))
				//
				// span := spans.AppendEmpty()
				// span.SetName(*nameRes.(*string))
				// span.SetTraceID(tc.TraceID)
				// span.SetSpanID(tc.SpanID)
				// span.SetParentSpanID(tc.ParentSpanID)
			}
		}
	}
	return traces, nil
}
