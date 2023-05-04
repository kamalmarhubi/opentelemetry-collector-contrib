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
	"sync"
	// "time"

	// "github.com/lightstep/go-expohisto/structure"
	// "github.com/tilinna/clock"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	// "go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	// "go.opentelemetry.io/collector/pdata/ptrace"
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


type logtospan struct {
	lock   sync.Mutex
	settings component.TelemetrySettings
	
	config Config

	logsConsumer consumer.Logs
	traceContextGetter ottl.Statements[ottllog.TransformContext]

	done    chan struct{}
	started bool

	shutdownOnce sync.Once
}

func newConnector(settings component.TelemetrySettings, config component.Config) (*logtospan, error) {
	settings.Logger.Info("Building logtospan connector")
	cfg := config.(*Config)

	traceContextParser, err := ottllog.NewParser(internal.TraceContextFunctions(), settings)
	if err != nil {
		return nil, err
	}
	traceContextStatement, err := traceContextParser.ParseStatement(cfg.TraceContext)
	if err != nil {
		return nil, err
	}

	return &logtospan{
		settings: settings, 
		config:                *cfg,
		traceContextGetter: ottl.NewStatements([]*ottl.Statement[ottllog.TransformContext]{traceContextStatement}, settings),
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

func (c *logtospan) convertLogs(ctx context.Context, logs plog.Logs) error {
	for i := 0; i < logs.ResourceLogs().Len(); i++ {
		rlogs := logs.ResourceLogs().At(i)
		res := rlogs.Resource()

		ilsSlice := rlogs.ScopeLogs()
		for j := 0; j < ilsSlice.Len(); j++ {
			ils := ilsSlice.At(j)
			is := ils.Scope()
			lrs := ils.LogRecords()
			for k := 0; k < lrs.Len(); k++ {

				lr := lrs.At(k)
				tc, ran, err := c.traceContextGetter.Execute(ctx, ottllog.NewTransformContext(lr, is, res))
				c.settings.Logger.Info("lol", zap.Any("ahahah", lr), zap.Any("jkfdjs", internal.TraceContextFunctions()))
			}
		}
	}
	return nil
}

// aggregateMetrics aggregates the raw metrics from the input trace data.
//
// Metrics are grouped by resource attributes.
// Each metric is identified by a key that is built from the service name
// and span metadata such as name, kind, status_code and any additional
// dimensions the user has configured.
// func (c *logtospan) aggregateMetrics(traces ptrace.Traces) {
// 	for i := 0; i < traces.ResourceSpans().Len(); i++ {
// 		rspans := traces.ResourceSpans().At(i)
// 		resourceAttr := rspans.Resource().Attributes()
// 		serviceAttr, ok := resourceAttr.Get(conventions.AttributeServiceName)
// 		if !ok {
// 			continue
// 		}
//
// 		rm := c.getOrCreateResourceMetrics(resourceAttr)
// 		sums := rm.sums
// 		histograms := rm.histograms
//
// 		unitDivider := unitDivider(c.config.Histogram.Unit)
// 		serviceName := serviceAttr.Str()
// 		ilsSlice := rspans.ScopeSpans()
// 		for j := 0; j < ilsSlice.Len(); j++ {
// 			ils := ilsSlice.At(j)
// 			spans := ils.Spans()
// 			for k := 0; k < spans.Len(); k++ {
// 				span := spans.At(k)
// 				// Protect against end timestamps before start timestamps. Assume 0 duration.
// 				duration := float64(0)
// 				startTime := span.StartTimestamp()
// 				endTime := span.EndTimestamp()
// 				if endTime > startTime {
// 					duration = float64(endTime-startTime) / float64(unitDivider)
// 				}
// 				key := c.buildKey(serviceName, span, c.dimensions, resourceAttr)
//
// 				attributes, ok := c.metricKeyToDimensions.Get(key)
// 				if !ok {
// 					attributes = c.buildAttributes(serviceName, span, resourceAttr)
// 					c.metricKeyToDimensions.Add(key, attributes)
// 				}
//
// 				// aggregate histogram metrics
// 				h := histograms.GetOrCreate(key, attributes)
// 				h.Observe(duration)
// 				if !span.TraceID().IsEmpty() {
// 					h.AddExemplar(span.TraceID(), span.SpanID(), duration)
// 				}
//
// 				// aggregate sums metrics
// 				s := sums.GetOrCreate(key, attributes)
// 				s.Add(1)
// 			}
// 		}
// 	}
// }
