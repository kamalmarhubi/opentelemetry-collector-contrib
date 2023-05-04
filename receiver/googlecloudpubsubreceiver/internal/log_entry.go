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
	"bytes"
	"context"
	"encoding/hex"
	stdjson "encoding/json"
	jsoniter "github.com/json-iterator/go"

	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iancoleman/strcase"
	"go.uber.org/zap"

	"cloud.google.com/go/logging/apiv2/loggingpb"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/anypb"
)


var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

var desc protoreflect.MessageDescriptor
var descOnce sync.Once

func getLogEntryDescriptor() protoreflect.MessageDescriptor {
	descOnce.Do(func() {
		var logEntry loggingpb.LogEntry

		desc = logEntry.ProtoReflect().Descriptor()
	})

	return desc
}

func TranslateLogEntry(ctx context.Context, logger *zap.Logger, data []byte) (pcommon.Resource, plog.LogRecord, error) {
	lr := plog.NewLogRecord()
	res := pcommon.NewResource()

	var src map[string]stdjson.RawMessage
	err := json.Unmarshal(data, &src)

	if err != nil {
		return res, lr, err
	}

	resAttrs := res.Attributes()
	attrs := lr.Attributes()

	for k, v := range src {
		switch k {
		// Unpack as defiend in semantic conventions:
		//   https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/logs/data-model-appendix.md#google-cloud-logging
		case "timestamp":
			// timestamp -> Timestamp
			var t time.Time
			err = json.Unmarshal(v, &t)
			if err != nil {
				return res, lr, err
			}
			lr.SetTimestamp(pcommon.NewTimestampFromTime(t))
			delete(src, k)
		case "resource":
			// resource -> Resource
			// mapping type -> gcp.resource_type
			// labels -> gcp.<label>
			var protoRes monitoredres.MonitoredResource
			err = protojson.Unmarshal(v, &protoRes)

			resAttrs.EnsureCapacity(len(protoRes.GetLabels()) + 1)
			resAttrs.PutStr("gcp.resource_type", protoRes.GetType())
			for k, v := range protoRes.GetLabels() {
				resAttrs.PutStr(strcase.ToSnakeWithIgnore(fmt.Sprintf("gcp.%v", k), "."), v)
			}
			delete(src, k)
		case "logName":
			var logName string
			err = json.Unmarshal(v, &logName)
			if err != nil {
				return res, lr, err
			}
			// log_name -> Attributes[“gcp.log_name”]
			attrs.PutStr("gcp.log_name", logName)
			delete(src, k)
		case "jsonPayload", "textPayload":
			// {json,proto,text}_payload -> Body
			var payload any
			err = json.Unmarshal(v, &payload)
			if err != nil {
				return res, lr, err
			}
			lr.Body().FromRaw(payload)
			delete(src, k)
		case "protoPayload":
			// {json,proto,text}_payload -> Body
			err = translateInto(lr.Body().SetEmptyMap(), (&anypb.Any{}).ProtoReflect().Descriptor(), v)
			if err != nil {
				return res, lr, err
			}
			delete(src, k)
		case "severity":
			var severity string
			err = json.Unmarshal(v, &severity)
			if err != nil {
				return res, lr, err
			}
			// severity -> Severity
			// According to the spec, this is the original string representation of
			// the severity as it is known at the source:
			//   https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-severitytext
			lr.SetSeverityText(severity)
			delete(src, k)
		case "trace":
			var trace string
			err = json.Unmarshal(v, &trace)
			if err != nil {
				return res, lr, err
			}
			lr.SetTraceID(cloudLoggingTraceToTraceIDBytes(trace))
			delete(src, k)
		case "spanId":
			var spanId string
			err = json.Unmarshal(v, &spanId)
			if err != nil {
				return res, lr, err
			}
			lr.SetSpanID(spanIDStrToSpanIDBytes(spanId))
			delete(src, k)
		case "labels":
			var labels map[string]string
			err = json.Unmarshal(v, &labels)
			if err != nil {
				return res, lr, err
			}
			// labels -> Attributes
			for k, v := range labels {
				attrs.PutStr(k, v)
			}
			delete(src, k)
		case "httpRequest":
			httpRequestAttrs := attrs.PutEmptyMap("gcp.http_request")
			err = translateInto(httpRequestAttrs, getLogEntryDescriptor().Fields().ByJSONName(k).Message(), v, snakeifyKeys)
			if err != nil {
				return res, lr, err
			}
			delete(src, k)
		default:
		}
	}

	// All other fields -> Attributes["gcp.*"]
	// At this point we cleared all the fields that have special handling.
	translateInto(attrs, getLogEntryDescriptor(), src, preserveDst, prefixKeys("gcp."), snakeifyKeys)

	return res, lr, nil
}

// should only translate maps?

func snakeify(s string) string {
	return strcase.ToSnakeWithIgnore(s, ".")
}

func prefix(p string) func(string) string {
	return func(s string) string {
		return p + s
	}
}

type translateOptions struct {
	keyMappers   []func(string) string
	preserveDst  bool
	useJsonNames bool
}

func NewTranslateOptions() translateOptions {
	return translateOptions{useJsonNames: true}
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

func getType(src stdjson.RawMessage) string {
	dec := stdjson.NewDecoder(bytes.NewReader(src))
	tok, err := dec.Token()
	if err != nil {
		return "invalid json"
	}
	switch t := tok.(type) {
	case stdjson.Delim:
		switch t {
		case '[':
			return "array"
		case '{':
			return "object"
		default:
			return "invalid json"
		}
	case bool:
		return "bool"
	case float64, stdjson.Number:
		return "number"
	case string:
		return "string"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

func translateStr(dst pcommon.Value, src stdjson.RawMessage) error {
	var val string
	err := json.Unmarshal(src, &val)
	if err != nil {
		return err
	}
	dst.SetStr(val)
	return nil
}

func translateRaw(dst pcommon.Value, src stdjson.RawMessage) error {
	var val any
	err := json.Unmarshal(src, &val)
	if err != nil {
		return err
	}
	dst.FromRaw(val)
	return nil
}

func (opts translateOptions) translateValue(dst pcommon.Value, fd protoreflect.FieldDescriptor, src stdjson.RawMessage) error {
	var err error
	switch fd.Kind() {
	case protoreflect.MessageKind:
		msg := fd.Message()
		switch fd.Message().FullName() {
		case "google.protobuf.Duration", "google.protobuf.Timestamp":
			// protojson represents both of these as strings
			return translateStr(dst, src)
		case "google.protobuf.Struct", "google.protobuf.Value":
			return translateRaw(dst, src)
		case
			"google.protobuf.BoolValue",
			"google.protobuf.BytesValue",
			"google.protobuf.DoubleValue",
			"google.protobuf.FloatValue",
			"google.protobuf.Int32Value",
			"google.protobuf.Int64Value",
			"google.protobuf.StringValue",
			"google.protobuf.UInt32Value",
			"google.protobuf.UInt64Value":
			// All the wrapper types have a single field with name
			// `value` and field number 1, and are represented in
			// protojson without the wrapping.
			innerFd := fd.Message().Fields().ByNumber(1)
			opts.translateValue(dst, innerFd, src)
		default:
			var m pcommon.Map
			switch dst.Type() {
			case pcommon.ValueTypeMap:
				m = dst.Map()
			default:
				m = dst.SetEmptyMap()
			}
			return translateInto(m, msg, src)
		}
	case protoreflect.EnumKind:
		// protojson accepts either string name or enum int value; try both.
		if translateStr(dst, src) == nil {
			return nil
		}

		enum := fd.Enum()
		var i int32
		if err = json.Unmarshal(src, &i); err != nil {
			return fmt.Errorf("wrong type for enum: %v", getType(src))
		}
		enumValue := enum.Values().ByNumber(protoreflect.EnumNumber(i))
		if enumValue == nil {
			return fmt.Errorf("%v has no enum value for %v", enum.FullName(), i)
		}

		dst.SetStr(string(enumValue.Name()))
	case protoreflect.BoolKind:
		var val bool
		err := json.Unmarshal(src, &val)
		if err != nil {
			return err
		}
		dst.SetBool(val)
	case protoreflect.Int32Kind,
		protoreflect.Uint32Kind,
		protoreflect.Sfixed32Kind,
		protoreflect.Fixed32Kind,
		protoreflect.Sint32Kind,
		protoreflect.Int64Kind,
		protoreflect.Uint64Kind,
		protoreflect.Sfixed64Kind,
		protoreflect.Fixed64Kind,
		protoreflect.Sint64Kind:
		// The protojson encoding accepts either string or number for
		// integer types, so try both.
		var val int64
		if json.Unmarshal(src, &val) == nil {
			dst.SetInt(val)
			return nil
		}

		var s string
		if err = json.Unmarshal(src, &s); err != nil {
			return err
		}
		if val, err = strconv.ParseInt(s, 10, 64); err != nil {
			return err
		}
		dst.SetInt(val)
		return nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		var val float64
		err := json.Unmarshal(src, &val)
		if err != nil {
			return err
		}
		dst.SetDouble(val)
		return nil
	case protoreflect.BytesKind:
		var val []byte
		err := json.Unmarshal(src, &val)
		if err != nil {
			return err
		}
		dst.SetEmptyBytes().Append(val...)
		return nil
	case protoreflect.StringKind:
		return translateStr(dst, src)
	case protoreflect.GroupKind:
		return errors.New("unexpected group")
	default:
		return errors.New("unknown field kind")
	}
	return nil
}

func (opts translateOptions) translateList(dst pcommon.Slice, fd protoreflect.FieldDescriptor, src stdjson.RawMessage) error {
	var msg []stdjson.RawMessage
	if err := json.Unmarshal(src, &msg); err != nil {
		return err
	}

	for _, v := range msg {
		err := opts.translateValue(dst.AppendEmpty(), fd, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (opts translateOptions) translateMap(dst pcommon.Map, fd protoreflect.FieldDescriptor, src stdjson.RawMessage) error {
	var msg map[string]stdjson.RawMessage
	if err := json.Unmarshal(src, &msg); err != nil {
		return err
	}
	for k, v := range msg {
		err := opts.translateValue(dst.PutEmpty(k), fd.MapValue(), v)
		if err != nil {
			return err
		}
	}
	return nil
}
func translateAny(dst pcommon.Map, src map[string]stdjson.RawMessage) error {
	// protojson reprsents Any as the JSON representation of the actual
	// message, plus a special @type field containing the type URL of the
	// message.
	typeUrl, ok := src["@type"]
	if !ok {
		return errors.New("no @type member in Any message")
	}
	var typeUrlStr string
	if err := json.Unmarshal(typeUrl, &typeUrlStr); err != nil {
		return err
	}
	delete(src, "@type")

	msgType, err := protoregistry.GlobalTypes.FindMessageByURL(typeUrlStr)
	if errors.Is(err, protoregistry.NotFound) {
		// If we don't have the type, we do a best-effort JSON parse;
		// some ints might be floats or strings.
		for k, v := range src {
			var val any
			err := json.Unmarshal(v, &val)
			if err !=  nil {
				return nil
			}
			dst.PutEmpty(k).FromRaw(val)
		}
		return nil
	}

	err = translateInto(dst, msgType.Descriptor(), src)
	if err != nil {
		return err
	}

	dst.PutStr("@type", typeUrlStr)
	return nil
}

func (opts translateOptions) translateMessage(dst pcommon.Map, desc protoreflect.MessageDescriptor, src map[string]stdjson.RawMessage) error {
	log.Printf("??? %v", desc.FullName())
	if !opts.preserveDst {
		dst.Clear()
	}

	// Handle well-known aggregate types.
	switch desc.FullName() {
	case "google.protobuf.Any":
		return translateAny(dst, src)
	case "google.protobuf.Struct":
		for k, v := range src {
			var val any
			if err := json.Unmarshal(v, &val); err != nil {
				return err
			}
			dst.PutEmpty(k).FromRaw(val)
		}
		return nil
	case "google.protobuf.Empty":
		dst.Clear()
		return nil
	default:
	}

	for k, v := range src {
		log.Printf("JKLFD %v", k)
		key := opts.mapKey(k)
		fd := desc.Fields().ByJSONName(k)
		if fd == nil {
			return fmt.Errorf("%v has no known field with JSON name %v", desc.FullName(), k)
		}
		var err error
		switch {
		case fd.IsList():
			err = opts.translateList(dst.PutEmptySlice(key), fd, v)
		case fd.IsMap():
			err = opts.translateMap(dst.PutEmptyMap(key), fd, v)
		default:
			err = opts.translateValue(dst.PutEmpty(key), fd, v)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func translateInto(dst pcommon.Map, desc protoreflect.MessageDescriptor, src any, opts ...opt) error {
	log.Printf("WTF %v", desc.FullName())
	var toTranslate map[string]stdjson.RawMessage

	switch msg := src.(type) {
	case stdjson.RawMessage:
		err := json.Unmarshal(msg, &toTranslate)
		if err != nil {
			return err
		}
	case map[string]stdjson.RawMessage:
		toTranslate = msg
	}

	options := translateOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	return options.translateMessage(dst, desc, toTranslate)
}
