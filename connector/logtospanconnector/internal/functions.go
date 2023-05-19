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
	"context"
	// 	"fmt"
	//
	"errors"
	"log"
	//
	// 	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pcommon"
	//
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/logtospan"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"
)

type FactoryMap map[string]ottl.Factory[logtospan.TransformContext]

func TraceContextFunctions() FactoryMap {
	return ottl.CreateFactoryMap(
		ottlfuncs.NewTraceIDFactory[logtospan.TransformContext](),
		ottlfuncs.NewSpanIDFactory[logtospan.TransformContext](),
		ottlfuncs.NewIsMatchFactory[logtospan.TransformContext](),
		ottlfuncs.NewConcatFactory[logtospan.TransformContext](),
		ottlfuncs.NewSplitFactory[logtospan.TransformContext](),
		ottlfuncs.NewIntFactory[logtospan.TransformContext](),
		ottlfuncs.NewConvertCaseFactory[logtospan.TransformContext](),
		ottlfuncs.NewParseJSONFactory[logtospan.TransformContext](),
		ottlfuncs.NewSubstringFactory[logtospan.TransformContext](),
		ottlfuncs.NewMergeMapsFactory[logtospan.TransformContext](),
		ottlfuncs.NewSetFactory[logtospan.TransformContext](),
		newFromFactory[logtospan.TransformContext](),
		newFromLogRecordFactory(),
		newStringFactory(),
	)
}

type TraceContext struct {
	TraceID      pcommon.TraceID
	SpanID       pcommon.SpanID
	ParentSpanID pcommon.SpanID
	TraceState   pcommon.TraceState
}

func (tc TraceContext) IsValid() bool {
	return !tc.TraceID.IsEmpty() && !tc.SpanID.IsEmpty()
}

type StringArguments[K any] struct {
	Target ottl.Getter[K] `ottlarg:"0"`
}

func newStringFactory() ottl.Factory[logtospan.TransformContext] {
	return ottl.NewFactory("String", &StringArguments[logtospan.TransformContext]{}, createStringFunction)
}

func createStringFunction(fCtx ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[logtospan.TransformContext], error) {
	args, ok := oArgs.(*StringArguments[logtospan.TransformContext])

	if !ok {
		return nil, errors.New("String args must be of type *StringArguments[K]")
	}

	return stringF(args.Target)
}

func stringF(target ottl.Getter[logtospan.TransformContext]) (ottl.ExprFunc[logtospan.TransformContext], error) {
	return func(ctx context.Context, tCtx logtospan.TransformContext) (interface{}, error) {
		lr := tCtx.GetLogRecord()

		tc := TraceContext{TraceID: lr.TraceID(), SpanID: lr.SpanID()}
		if tc.IsValid() {
			return tc, nil
		}

		return TraceContext{}, nil
	}, nil
}

type FromArguments[K any] struct {
	Target ottl.StringLikeGetter[K] `ottlarg:"0"`
}

func newFromFactory[K any]() ottl.Factory[K] {
	log.Printf("WTF")
	return ottl.NewFactory("from", &FromArguments[K]{}, createFromFunction[K])
}

func createFromFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*FromArguments[K])

	if !ok {
		return nil, errors.New("from args must be of type *FromArguments[K]")
	}

	return from(args)
}

func from[K any](args *FromArguments[K]) (ottl.ExprFunc[K], error) {
	return func(ctx context.Context, tCtx K) (interface{}, error) {
		return args.Target.Get(ctx, tCtx)
	}, nil
}

func newFromLogRecordFactory() ottl.Factory[logtospan.TransformContext] {
	return ottl.NewFactory("from_log_record", &struct{}{}, createFromLogRecordFunction)
}

func createFromLogRecordFunction(_ ottl.FunctionContext, _ ottl.Arguments) (ottl.ExprFunc[logtospan.TransformContext], error) {
	return fromLogRecord()
}

func fromLogRecord() (ottl.ExprFunc[logtospan.TransformContext], error) {
	return func(ctx context.Context, tCtx logtospan.TransformContext) (interface{}, error) {
		lr := tCtx.GetLogRecord()

		tc := TraceContext{TraceID: lr.TraceID(), SpanID: lr.SpanID()}
		if tc.IsValid() {
			return tc, nil
		}

		return TraceContext{}, nil
	}, nil
}
