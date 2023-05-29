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
	"fmt"
	"github.com/google/go-cmp/cmp"
	"testing"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/pcommon"
	// "go.opentelemetry.io/collector/pdata/plog"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

func Test_ParseStructuredFieldValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]any
	}{
		{
			name:     "empty",
			input:    "",
			expected: map[string]any{},
		},
		{
			name:     "single string",
			input:    `a="abc"`,
			expected: map[string]any{"a": "abc"},
		},
		{
			name:     "multiple types",
			input:    `s="abc",b=?1,i=123,d=123.0`,
			expected: map[string]any{"s": "abc", "b": true, "i": int64(123), "d": float64(123.0)},
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			target := ottl.StandardTypeGetter[any, string]{
				Getter: func(ctx context.Context, tCtx any) (interface{}, error) {
					return tt.input, nil
				},
			}
			exprFunc := parseStructuredFieldValues[any](target)
			result, err := exprFunc(context.Background(), nil)

			assert.NoError(t, err)

			m, ok := result.(pcommon.Map)
			assert.True(t, ok)
			assert.NoError(t, compare("map[string]any", tt.expected, m.AsRaw()))

		})
	}
}
func compare(ty string, expected, actual any, opts ...cmp.Option) error {
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		return fmt.Errorf("%s mismatch (-expected +actual):\n%s", ty, diff)
	}
	return nil
}
