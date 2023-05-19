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
	"go.opentelemetry.io/collector/component"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl"
)

var _ component.Config = (*Config)(nil)

type Config struct {
	// ErrorMode determines how the processor reacts to errors that occur while processing a statement.
	// Valid values are `ignore` and `propagate`.
	// `ignore` means the processor ignores errors returned by statements and continues on to the next statement. This is the recommended mode.
	// `propagate` means the processor returns the error up the pipeline.  This will result in the payload being dropped from the collector.
	// The default value is `propagate`.
	ErrorMode ottl.ErrorMode `mapstructure:"error_mode"`
	Statements []string  `mapstructure:"statements"`
}

func (config *Config) Validate() error {
	// do the parse
	return nil
}
