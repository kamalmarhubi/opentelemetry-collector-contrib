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

package awss3exporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/awss3exporter"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

type s3Exporter struct {
	config     *Config
	dataWriter dataWriter
	logger     *zap.Logger
	marshaler  marshaler
}

func newS3Exporter(config *Config,
	params exporter.CreateSettings) (*s3Exporter, error) {

	if config == nil {
		return nil, errors.New("s3 exporter config is nil")
	}

	logger := params.Logger

	m, err := NewMarshaler(config.MarshalerName, logger)
	if err != nil {
		return nil, errors.New("unknown marshaler")
	}

	s3Exporter := &s3Exporter{
		config:     config,
		dataWriter: &s3Writer{},
		logger:     logger,
		marshaler:  m,
	}
	return s3Exporter, nil
}

func (e *s3Exporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (e *s3Exporter) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	buf, err := e.marshaler.MarshalMetrics(md)

	if err != nil {
		return err
	}

	return e.dataWriter.writeBuffer(ctx, buf, e.config, "metrics", e.marshaler.format())
}

func (e *s3Exporter) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	buf, err := e.marshaler.MarshalLogs(logs)

	if err != nil {
		return err
	}

	return e.dataWriter.writeBuffer(ctx, buf, e.config, "logs", e.marshaler.format())
}

func (e *s3Exporter) ConsumeTraces(ctx context.Context, traces ptrace.Traces) error {
	buf, err := e.marshaler.MarshalTraces(traces)
	if err != nil {
		return err
	}

	return e.dataWriter.writeBuffer(ctx, buf, e.config, "traces", e.marshaler.format())
}
