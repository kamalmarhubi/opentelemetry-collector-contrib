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
// 	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pcommon"
//
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/ottllog"
)

func TraceContextFunctions() map[string]ottl.Factory[ottllog.TransformContext] {
	return ottl.CreateFactoryMap(newFromLogRecordFactory())
}

func newFromLogRecordFactory() ottl.Factory[ottllog.TransformContext] {
	return ottl.NewFactory("FromLogRecord", &struct{}{}, createFromLogRecordFunction)
}

func createFromLogRecordFunction(fCtx ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[ottllog.TransformContext], error) {
	return fromLogRecord()
}

type TraceContext struct {
	TraceID pcommon.TraceID
	SpanID pcommon.SpanID
}

func (tc TraceContext) IsValid() bool {
	return !tc.TraceID.IsEmpty() && !tc.SpanID.IsEmpty()
}

func fromLogRecord() (ottl.ExprFunc[ottllog.TransformContext], error) {
	return func(ctx context.Context, tCtx ottllog.TransformContext) (interface{}, error) {
		lr := tCtx.GetLogRecord()

		tc := TraceContext{TraceID: lr.TraceID(), SpanID: lr.SpanID()}
		if tc.IsValid() {
			return tc, nil
		}

		return TraceContext{}, nil
	}, nil
}
//
// func hasAttributeKeyOnDatapoint(key string) (ottl.ExprFunc[ottllog.TransformContext], error) {
// 	return func(ctx context.Context, tCtx ottllog.TransformContext) (interface{}, error) {
// 		return checkDataPoints(tCtx, key, nil)
// 	}, nil
// }
//
// func checkDataPoints(tCtx ottllog.TransformContext, key string, expectedVal *string) (interface{}, error) {
// 	metric := tCtx.GetMetric()
// 	switch metric.Type() {
// 	case pmetric.MetricTypeSum:
// 		return checkNumberDataPointSlice(metric.Sum().DataPoints(), key, expectedVal), nil
// 	case pmetric.MetricTypeGauge:
// 		return checkNumberDataPointSlice(metric.Gauge().DataPoints(), key, expectedVal), nil
// 	case pmetric.MetricTypeHistogram:
// 		return checkHistogramDataPointSlice(metric.Histogram().DataPoints(), key, expectedVal), nil
// 	case pmetric.MetricTypeExponentialHistogram:
// 		return checkExponentialHistogramDataPointSlice(metric.ExponentialHistogram().DataPoints(), key, expectedVal), nil
// 	case pmetric.MetricTypeSummary:
// 		return checkSummaryDataPointSlice(metric.Summary().DataPoints(), key, expectedVal), nil
// 	}
// 	return nil, fmt.Errorf("unknown metric type")
// }
//
// func checkNumberDataPointSlice(dps pmetric.NumberDataPointSlice, key string, expectedVal *string) bool {
// 	for i := 0; i < dps.Len(); i++ {
// 		dp := dps.At(i)
// 		value, ok := dp.Attributes().Get(key)
// 		if ok {
// 			if expectedVal != nil {
// 				return value.Str() == *expectedVal
// 			}
// 			return true
// 		}
// 	}
// 	return false
// }
//
// func checkHistogramDataPointSlice(dps pmetric.HistogramDataPointSlice, key string, expectedVal *string) bool {
// 	for i := 0; i < dps.Len(); i++ {
// 		dp := dps.At(i)
// 		value, ok := dp.Attributes().Get(key)
// 		if ok {
// 			if expectedVal != nil {
// 				return value.Str() == *expectedVal
// 			}
// 			return true
// 		}
// 	}
// 	return false
// }
//
// func checkExponentialHistogramDataPointSlice(dps pmetric.ExponentialHistogramDataPointSlice, key string, expectedVal *string) bool {
// 	for i := 0; i < dps.Len(); i++ {
// 		dp := dps.At(i)
// 		value, ok := dp.Attributes().Get(key)
// 		if ok {
// 			if expectedVal != nil {
// 				return value.Str() == *expectedVal
// 			}
// 			return true
// 		}
// 	}
// 	return false
// }
//
// func checkSummaryDataPointSlice(dps pmetric.SummaryDataPointSlice, key string, expectedVal *string) bool {
// 	for i := 0; i < dps.Len(); i++ {
// 		dp := dps.At(i)
// 		value, ok := dp.Attributes().Get(key)
// 		if ok {
// 			if expectedVal != nil {
// 				return value.Str() == *expectedVal
// 			}
// 			return true
// 		}
// 	}
// 	return false
// }
