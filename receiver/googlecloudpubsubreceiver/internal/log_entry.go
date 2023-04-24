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

package internal // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/googlecloudpubsubreceiver/internal"

import (
	"context"
	"encoding/hex"
	"strings"
	"fmt"
	"strconv"


	"github.com/iancoleman/strcase"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"cloud.google.com/go/logging/apiv2/loggingpb"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var invalidTraceID = [16]byte{}
var invalidSpanID = [8]byte{}

func cloudLoggingTraceToTraceIDBytes(trace string) [16]byte {
	// Format: projects/my-gcp-project/traces/4ebc71f1def9274798cac4e8960d0095
	lastSlashIdx := strings.LastIndex(trace, "/")
	if lastSlashIdx == -1 {
		return invalidTraceID
	}
	traceIDStr := trace[lastSlashIdx+1:]

	return traceIDStrTotraceIDBytes(traceIDStr)
}

func traceIDStrTotraceIDBytes(traceIDStr string) [16]byte {
	traceIDSlice := [16]byte{}
	decoded, err := hex.Decode(traceIDSlice[:], []byte(traceIDStr))
	if err != nil || decoded != 16 {
		return invalidTraceID
	}

	return traceIDSlice
}

func spanIDStrToSpanIDBytes(spanIDStr string) [8]byte {
	spanIDSlice := [8]byte{}
	decoded, err := hex.Decode(spanIDSlice[:], []byte(spanIDStr))
	if err != nil || decoded != 8 {
		return invalidSpanID
	}

	return spanIDSlice
}

func TranslateLogEntry(ctx context.Context, logger *zap.Logger, data []byte) (pcommon.Resource, plog.LogRecord, error) {
	var logEntry loggingpb.LogEntry

	lr := plog.NewLogRecord()
	res := pcommon.NewResource()

	err := protojson.Unmarshal(data, &logEntry)
	if err != nil {
		return res, lr, err
	}

	resAttrs := res.Attributes()
	attrs := lr.Attributes()



	reflected := logEntry.ProtoReflect()
	reflected.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		jsonName := fd.JSONName()
		switch(jsonName) {
		// Unpack as defiend in semantic conventions:
		//   https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model-appendix.md#google-cloud-logging
		case "timestamp":
			// timestamp -> Timestamp
			lr.SetTimestamp(pcommon.NewTimestampFromTime(logEntry.GetTimestamp().AsTime()))
			reflected.Clear(fd)
		case "resource":
			// resource -> Resource
			// mapping type -> gcp.resource_type
			// labels -> gcp.<label>
			monitoredResource := logEntry.GetResource()
			resType := monitoredResource.GetType()
			resAttrs.EnsureCapacity(len(monitoredResource.GetLabels()) + 1)
			resAttrs.PutStr("gcp.resource_type", resType)
			for k, v := range(monitoredResource.GetLabels()) {
				resAttrs.PutStr(strcase.ToSnakeWithIgnore(fmt.Sprintf("gcp.%v", k), "."), v)
			}
			reflected.Clear(fd)
		case "logName":
			// log_name -> Attributes[“gcp.log_name”]
			attrs.PutStr("gcp.log_name", logEntry.GetLogName())
		case "jsonPayload":
			// {json,proto,text}_payload -> Body
			translateStruct(lr.Body().SetEmptyMap(), logEntry.GetJsonPayload())
			reflected.Clear(fd)
		case "protoPayload":
			// {json,proto,text}_payload -> Body
			translateAny(lr.Body().SetEmptyMap(), logEntry.GetProtoPayload())
			reflected.Clear(fd)
		case "textPayload":
			// {json,proto,text}_payload -> Body
			lr.Body().SetStr(logEntry.GetTextPayload())
			reflected.Clear(fd)
		case "severity":
			// severity -> Severity
			// According to the spec, this is the original string representation of
			// the severity as it is known at the source:
			//   https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-severitytext
			lr.SetSeverityText(logEntry.GetSeverity().String())
			reflected.Clear(fd)
		case "trace":
			lr.SetTraceID(cloudLoggingTraceToTraceIDBytes(logEntry.GetTrace()))
			reflected.Clear(fd)
		case "spanId":
			lr.SetSpanID(spanIDStrToSpanIDBytes(logEntry.GetSpanId()))
			reflected.Clear(fd)
		case "labels":
			// labels -> Attributes
			for k, v := range(logEntry.GetLabels()) {
				attrs.PutStr(k, v)
			}
			reflected.Clear(fd)
		case "httpRequest":
			// http_request -> Attributes[“gcp.http_request”]
			if httpRequest := logEntry.GetHttpRequest(); httpRequest != nil {
				httpRequestAttrs := attrs.PutEmptyMap("gcp.http_request")
				translateInto(httpRequestAttrs, httpRequest.ProtoReflect(), snakeifyKeys)
			}
			reflected.Clear(fd)
		default:
		}
		return true
	})
	// All other fields -> Attributes["gcp.*"]
	// At this point we cleared all the fields that have special handling.
	translateInto(attrs, reflected, preserveDst, prefixKeys("gcp."), snakeifyKeys)

	return res, lr, nil
}

// should only translate maps?

func snakeify(s string) string {
  return strcase.ToSnakeWithIgnore(s, ".")
}

func prefix(p string) func (string) string {
	return func(s string) string {
		return p+s
	}
}

type translateOptions struct {
	keyMappers []func(string) string
	preserveDst bool
	useJsonNames bool
}

func NewTranslateOptions() translateOptions {
	return translateOptions{ useJsonNames: true }
}

type opt func(*translateOptions)

func useJsonNames(opts *translateOptions) {
	opts.useJsonNames = true
}

func preserveDst(opts *translateOptions) {
	opts.preserveDst = true
}

func snakeifyKeys(opts *translateOptions) {
	opts.keyMappers = append(opts.keyMappers, snakeify)
}

func prefixKeys(p string) opt {
	return func(opts *translateOptions) {
		opts.keyMappers = append(opts.keyMappers, prefix(p))
	}
}

func (opts translateOptions) mapKey(s string) string {
	for _, mapper := range opts.keyMappers {
		s = mapper(s)
	}

	return s
}

func (opts translateOptions) translateValue(dst pcommon.Value, fd protoreflect.FieldDescriptor, src protoreflect.Value) {
	switch fd.Kind() {
	case protoreflect.MessageKind:
		switch reflected := src.Message(); unreflected := reflected.Interface().(type) {
		case *durationpb.Duration, *timestamppb.Timestamp:
			// HACK: use protojson to format these back to how they were present in the original message; requires stripping the quotes.
			str := protojson.Format(unreflected)
			str, err := strconv.Unquote(str)
			if err != nil {
				pcommon.NewValueEmpty().CopyTo(dst)
			}
			dst.SetStr(str)
		case *structpb.Value:
			translateWktValue(dst, unreflected)
		case *wrapperspb.DoubleValue:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.FloatValue:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.Int64Value:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.UInt64Value:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.Int32Value:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.UInt32Value:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.BoolValue:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.StringValue:
			dst.FromRaw(unreflected.GetValue())
		case *wrapperspb.BytesValue:
			dst.FromRaw(unreflected.GetValue())
		default:
			var m pcommon.Map
			switch dst.Type() {
			case pcommon.ValueTypeMap:
				m = dst.Map()
			default:
				m = dst.SetEmptyMap()
			}
			translateInto(m, reflected)
		}
	case protoreflect.EnumKind:
		enumValue := fd.Enum().Values().ByNumber(src.Enum())
		if enumValue != nil {
			dst.SetStr(string(enumValue.Name()))
		}
	case
	// All the scalars can be handled by going via go native types.
	protoreflect.BoolKind,
	// Signed ints
	protoreflect.Int32Kind, protoreflect.Int64Kind,
	protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind,
	protoreflect.Sint32Kind, protoreflect.Sint64Kind,
	// Unsigned ints
	protoreflect.Uint32Kind, protoreflect.Uint64Kind,
	protoreflect.Fixed32Kind, protoreflect.Fixed64Kind,
	// Floats
	protoreflect.FloatKind, protoreflect.DoubleKind,
	// Not-quite-scalars?
	protoreflect.BytesKind,
	protoreflect.StringKind:
		err := dst.FromRaw(src.Interface())
		if err != nil {
			pcommon.NewValueEmpty().CopyTo(dst)
		}
	case protoreflect.GroupKind:
		// proto3 has no groups.
		break
	default:
		break
	}
}

func (opts translateOptions) translateList(dst pcommon.Slice, fd protoreflect.FieldDescriptor, list protoreflect.List) {
	for i := 0; i < list.Len(); i++ {
		item := list.Get(i)
		opts.translateValue(dst.AppendEmpty(), fd, item)
	}
}

func (opts translateOptions) translateMap(dst pcommon.Map, fd protoreflect.FieldDescriptor, m protoreflect.Map) {
	m.Range(func (k protoreflect.MapKey, v protoreflect.Value) bool {
		opts.translateValue(dst.PutEmpty(k.String()), fd, v)
		return true
	})
}
func translateAny(dst pcommon.Map, src *anypb.Any) {
	if src == nil {
		return
	}
	// Mimic the protojson marshaling of Any.
	inner, err := src.UnmarshalNew()
	if err == nil {
		translateInto(dst, inner.ProtoReflect())
	}
	dst.PutStr("@type", src.TypeUrl)
}

func translateWktValue(dst pcommon.Value, src *structpb.Value) {
	if src != nil {
		dst.FromRaw(src.AsInterface())
	}
}

func translateStruct(dst pcommon.Map, src *structpb.Struct) {
	if src == nil {
		return
	}
	for k, v := range src.Fields {
		if v != nil {
			translateWktValue(dst.PutEmpty(k), v)
		}
	}
}

func (opts translateOptions) translateMessage(dst pcommon.Map, src protoreflect.Message) {
	if (!opts.preserveDst) {
		dst.Clear()
	}

	// Handle well-known aggregate types.
	switch message := src.Interface().(type) {
	case *anypb.Any:
		translateAny(dst, message)
		return
	case *structpb.Struct:
		translateStruct(dst, message)
		return
	case *emptypb.Empty:
		dst.Clear()
		return
	default:
	}

	src.Range(func (fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		key := opts.mapKey(fd.JSONName())

		switch {
		case fd.IsList():
			opts.translateList(dst.PutEmptySlice(key), fd, v.List())
		case fd.IsMap():
			opts.translateMap(dst.PutEmptyMap(key), fd, v.Map())
		default:
			if fd.Cardinality() != protoreflect.Optional {
				// TODO: error out ? report metric ? ignore ?
				panic("should not have other cardinality at this point")
			}
			opts.translateValue(dst.PutEmpty(key), fd, v)
		}

		return true
	})
}

func translateInto(dst pcommon.Map, src protoreflect.Message, opts ...opt) {
	options := translateOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	options.translateMessage(dst, src)
}
