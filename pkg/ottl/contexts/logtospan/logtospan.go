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

package logtospan // import "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/logtospan"

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/internal"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/internal/ottlcommon"
)

type TransformContext struct {
	logRecord            plog.LogRecord
	resource             pcommon.Resource
	instrumentationScope pcommon.InstrumentationScope
	span                 ptrace.Span
	cache                pcommon.Map
}

type Option func(*ottl.Parser[TransformContext])

func NewTransformContext(resource pcommon.Resource, instrumentationScope pcommon.InstrumentationScope, log plog.LogRecord, span ptrace.Span) TransformContext {
	return TransformContext{
		logRecord:            log,
		resource:             resource,
		instrumentationScope: instrumentationScope,
		span:                 span,
		cache:                pcommon.NewMap(),
	}
}

func (tCtx TransformContext) getCache() pcommon.Map {
	return tCtx.cache
}

func (tCtx TransformContext) GetResource() pcommon.Resource {
	return tCtx.resource
}

func (tCtx TransformContext) GetInstrumentationScope() pcommon.InstrumentationScope {
	return tCtx.instrumentationScope
}

func (tCtx TransformContext) GetLogRecord() plog.LogRecord {
	return tCtx.logRecord
}

func (tCtx TransformContext) GetSpan() ptrace.Span {
	return tCtx.span
}

func NewParser(functions map[string]ottl.Factory[TransformContext], telemetrySettings component.TelemetrySettings, options ...Option) (ottl.Parser[TransformContext], error) {
	p, err := ottl.NewParser[TransformContext](
		functions,
		parsePath,
		telemetrySettings,
		// ottl.WithEnumParser[TransformContext](parseEnum),
	)
	if err != nil {
		return ottl.Parser[TransformContext]{}, err
	}
	for _, opt := range options {
		opt(&p)
	}
	return p, nil
}

func NewStatements(statements []*ottl.Statement[TransformContext], telemetrySettings component.TelemetrySettings, options ...ottl.StatementsOption[TransformContext]) ottl.Statements[TransformContext] {
	s := ottl.NewStatements(statements, telemetrySettings)
	for _, op := range options {
		op(&s)
	}
	return s
}

func parsePath(val *ottl.Path) (ottl.GetSetter[TransformContext], error) {
	if val != nil && len(val.Fields) > 0 {
		return newPathGetSetter(val.Fields)
	}
	return nil, fmt.Errorf("bad path %v", val)
}

func newPathGetSetter(path []ottl.Field) (ottl.GetSetter[TransformContext], error) {
	switch path[0].Name {
	case "cache":
		mapKey := path[0].Keys
		if mapKey == nil {
			return accessCache(), nil
		}
		return accessCacheKey(mapKey), nil
	// TODO: ideally these next three would be read-only?
	case "log":
		return newLogPathGetSetter(path[1:])
	case "resource":
		return internal.ResourcePathGetSetter[TransformContext](path[1:])
	case "instrumentation_scope":
		return internal.ScopePathGetSetter[TransformContext](path[1:])
	default:
		// case "span":
		log.Printf("it's a span?????????????????????")
		return internal.SpanPathGetSetter[TransformContext](path)
	}
}

// func logPathGetSetter struct {
// 	log plog.LogRecord
// }

func newLogPathGetSetter(path []ottl.Field) (ottl.GetSetter[TransformContext], error) {
	switch path[0].Name {
	case "time_unix_nano":
		return accessTimeUnixNano(), nil
	case "observed_time_unix_nano":
		return accessObservedTimeUnixNano(), nil
	case "severity_number":
		return accessSeverityNumber(), nil
	case "severity_text":
		return accessSeverityText(), nil
	case "body":
		return accessBody(), nil
	case "attributes":
		mapKey := path[0].Keys
		if mapKey == nil {
			return accessAttributes(), nil
		}
		return accessAttributesKey(mapKey), nil
	case "dropped_attributes_count":
		return accessDroppedAttributesCount(), nil
	case "flags":
		return accessFlags(), nil
	case "trace_id":
		if len(path) == 1 {
			return accessTraceID(), nil
		}
		if path[1].Name == "string" {
			return accessStringTraceID(), nil
		}
	case "span_id":
		if len(path) == 1 {
			return accessSpanID(), nil
		}
		if path[1].Name == "string" {
			return accessStringSpanID(), nil
		}
	}
	return nil, fmt.Errorf("invalid path expression %v", path)
}

func accessCache() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.getCache(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if m, ok := val.(pcommon.Map); ok {
				m.CopyTo(tCtx.getCache())
			}
			return nil
		},
	}
}

func accessCacheKey(keys []ottl.Key) ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return internal.GetMapValue(tCtx.getCache(), keys)
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			return internal.SetMapValue(tCtx.getCache(), keys, val)
		},
	}
}

func accessTimeUnixNano() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().Timestamp().AsTime().UnixNano(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if i, ok := val.(int64); ok {
				tCtx.GetLogRecord().SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, i)))
			}
			return nil
		},
	}
}

func accessObservedTimeUnixNano() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().ObservedTimestamp().AsTime().UnixNano(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if i, ok := val.(int64); ok {
				tCtx.GetLogRecord().SetObservedTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, i)))
			}
			return nil
		},
	}
}

func accessSeverityNumber() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return int64(tCtx.GetLogRecord().SeverityNumber()), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if i, ok := val.(int64); ok {
				tCtx.GetLogRecord().SetSeverityNumber(plog.SeverityNumber(i))
			}
			return nil
		},
	}
}

func accessSeverityText() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().SeverityText(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if s, ok := val.(string); ok {
				tCtx.GetLogRecord().SetSeverityText(s)
			}
			return nil
		},
	}
}

func accessBody() ottl.StandardGetSetter[TransformContext] {
	log.Printf("WTF IS IT")
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			log.Printf("HI GETTING VALUE")
			return ottlcommon.GetValue(tCtx.GetLogRecord().Body()), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			return internal.SetValue(tCtx.GetLogRecord().Body(), val)
		},
	}
}

func accessAttributes() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().Attributes(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if attrs, ok := val.(pcommon.Map); ok {
				attrs.CopyTo(tCtx.GetLogRecord().Attributes())
			}
			return nil
		},
	}
}

func accessAttributesKey(keys []ottl.Key) ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return internal.GetMapValue(tCtx.GetLogRecord().Attributes(), keys)
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			return internal.SetMapValue(tCtx.GetLogRecord().Attributes(), keys, val)
		},
	}
}

func accessDroppedAttributesCount() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return int64(tCtx.GetLogRecord().DroppedAttributesCount()), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if i, ok := val.(int64); ok {
				tCtx.GetLogRecord().SetDroppedAttributesCount(uint32(i))
			}
			return nil
		},
	}
}

func accessFlags() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return int64(tCtx.GetLogRecord().Flags()), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if i, ok := val.(int64); ok {
				tCtx.GetLogRecord().SetFlags(plog.LogRecordFlags(i))
			}
			return nil
		},
	}
}

func accessTraceID() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().TraceID(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if newTraceID, ok := val.(pcommon.TraceID); ok {
				tCtx.GetLogRecord().SetTraceID(newTraceID)
			}
			return nil
		},
	}
}

func accessStringTraceID() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			id := tCtx.GetLogRecord().TraceID()
			return hex.EncodeToString(id[:]), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if str, ok := val.(string); ok {
				id, err := internal.ParseTraceID(str)
				if err != nil {
					return err
				}
				tCtx.GetLogRecord().SetTraceID(id)
			}
			return nil
		},
	}
}

func accessSpanID() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			return tCtx.GetLogRecord().SpanID(), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if newSpanID, ok := val.(pcommon.SpanID); ok {
				tCtx.GetLogRecord().SetSpanID(newSpanID)
			}
			return nil
		},
	}
}

func accessStringSpanID() ottl.StandardGetSetter[TransformContext] {
	return ottl.StandardGetSetter[TransformContext]{
		Getter: func(ctx context.Context, tCtx TransformContext) (interface{}, error) {
			id := tCtx.GetLogRecord().SpanID()
			return hex.EncodeToString(id[:]), nil
		},
		Setter: func(ctx context.Context, tCtx TransformContext, val interface{}) error {
			if str, ok := val.(string); ok {
				id, err := internal.ParseSpanID(str)
				if err != nil {
					return err
				}
				tCtx.GetLogRecord().SetSpanID(id)
			}
			return nil
		},
	}
}
