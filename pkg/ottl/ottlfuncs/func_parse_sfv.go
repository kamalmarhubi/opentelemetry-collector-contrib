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

package ottlfuncs // import "github.com/open-telemetry/opentelemetry-collector-contrib/connecctor/logtospanconnector/internal"

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
	"github.com/dunglas/httpsfv"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/contexts/logtospan"
	// "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl/ottlfuncs"
)


type ParseStructuredFieldValuesArguments[K any] struct {
	Target ottl.StringGetter[K] `ottlarg:"0"`
}

func NewParseStructuredFieldValuesFactory[K any]() ottl.Factory[K] {
	return ottl.NewFactory("ParseStructuredFieldValues", &ParseStructuredFieldValuesArguments[K]{}, createParseStructuredFieldValuesFunction[K])
}

func createParseStructuredFieldValuesFunction[K any](_ ottl.FunctionContext, oArgs ottl.Arguments) (ottl.ExprFunc[K], error) {
	args, ok := oArgs.(*ParseStructuredFieldValuesArguments[K])

	if !ok {
		return nil, errors.New("String args must be of type *ParseStructuredFieldValuesArguments[K]")
	}
	return parseStructuredFieldValues(args.Target), nil
}
func parseStructuredFieldValues[K any](target ottl.StringGetter[K]) ottl.ExprFunc[K] {
	return func(ctx context.Context, tCtx K) (interface{}, error) {
		targetVal, err := target.Get(ctx, tCtx)
		if err != nil {
			return nil, err
		}
		dict, err := httpsfv.UnmarshalDictionary([]string{targetVal})
		if err != nil {
			return nil, err
		}

		res := pcommon.NewMap()

		for _, k := range dict.Names() {
			member, present := dict.Get(k)
			if !present {
				log.Printf("WHY NOT PRESENT: %v", k)
				continue
			}
			switch v := member.(type) {
			case httpsfv.Item:
				res.PutEmpty(k).FromRaw(v.Value)
			default:
				log.Printf("NOT ITEM: %v", k)
				continue
			}
		}

		return res, nil

	}
}
