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

package internal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

type Log struct {
	Timestamp          string
	ObservedTimestamp  string
	Body               any
	SeverityText       string
	Attributes         map[string]any
	ResourceAttributes map[string]any
	SpanID             string
	TraceID            string
}

func generateLog(log Log) (pcommon.Resource, plog.LogRecord, error) {
	res := pcommon.NewResource()
	res.Attributes().FromRaw(log.ResourceAttributes)

	lr := plog.NewLogRecord()
	err := lr.Attributes().FromRaw(log.Attributes)
	if err != nil {
		return res, lr, err
	}
	if log.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339, log.Timestamp)
		if err != nil {
			return res, lr, err
		}
		lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	}

	if log.ObservedTimestamp != "" {
		ots, err := time.Parse(time.RFC3339, log.ObservedTimestamp)
		if err != nil {
			return res, lr, err
		}
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(ots))
	}

	lr.Body().FromRaw(log.Body)
	lr.SetSeverityText(log.SeverityText)

	lr.SetSpanID(spanIDStrToSpanIDBytes(log.SpanID))
	lr.SetTraceID(traceIDStrTotraceIDBytes(log.TraceID))

	return res, lr, nil
}

func TestTranslateLogEntry(t *testing.T) {

	tests := []struct {
		input string
		want  Log
	}{
		{
			// "labels": {
			//   "backend_service_name": "k8s1-14266937-default-app-aware-reverse-proxy-serv-808-161f7c20",
			//   "forwarding_rule_name": "k8s-fws-default-money-srv-web-ingress--142669370e5711a1",
			//   "project_id": "wavemm-174408",
			//   "target_proxy_name": "k8s-tps-default-money-srv-web-ingress--142669370e5711a1",
			//   "url_map_name": "k8s-um-default-money-srv-web-ingress--142669370e5711a1",
			//   "zone": "global"
			// },
			input: `
{
  "httpRequest": {
    "serverIp": "10.56.35.14",
    "status": 200,
    "userAgent": "com.wave.personal/23040401(Linux;U;Android10;fr_SN;OrangeNolafun;Build/QP1A.190711.020;Cronet/111.0.5563.55)",
    "responseSize": "1750",
    "latency": "0.248406s",
    "remoteIp": "41.82.183.143",
    "requestMethod": "POST",
    "requestSize": "522",
    "requestUrl": "https://sn.mmapp.wave.com/graphql"
  },
  "insertId": "mr6p8jfcxlde5",
  "jsonPayload": {
    "@type": "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
    "remoteIp": "41.82.183.143",
    "statusDetails": "response_sent_by_backend"
  },
  "logName": "projects/wavemm-174408/logs/requests",
  "receiveTimestamp": "2023-04-21T15:59:26.407178441Z",
  "resource": {
    "type": "http_load_balancer",
    "labels": {
      "backend_service_name": "k8s1-14266937-default-app-aware-reverse-proxy-serv-808-161f7c20",
      "forwarding_rule_name": "k8s-fws-default-money-srv-web-ingress--142669370e5711a1",
      "project_id": "wavemm-174408",
      "target_proxy_name": "k8s-tps-default-money-srv-web-ingress--142669370e5711a1",
      "url_map_name": "k8s-um-default-money-srv-web-ingress--142669370e5711a1",
      "zone": "global"
    }
  },
  "severity": "INFO",
  "spanId": "7a91e0b25edf30e0",
  "timestamp": "2023-04-21T15:59:24.827008Z",
  "trace": "projects/wavemm-174408/traces/4ebc71f1def9274798cac4e8960d0095"
}`,
			want: Log{ResourceAttributes: map[string]any{
				"gcp.resource_type":        "http_load_balancer",
				"gcp.backend_service_name": "k8s1-14266937-default-app-aware-reverse-proxy-serv-808-161f7c20",
				"gcp.forwarding_rule_name": "k8s-fws-default-money-srv-web-ingress--142669370e5711a1",
				"gcp.project_id":           "wavemm-174408",
				"gcp.target_proxy_name":    "k8s-tps-default-money-srv-web-ingress--142669370e5711a1",
				"gcp.url_map_name":         "k8s-um-default-money-srv-web-ingress--142669370e5711a1",
				"gcp.zone":                 "global",
			},
				Timestamp:    "2023-04-21T15:59:24.827008Z",
				SeverityText: "INFO",
				Body: map[string]any{
					"@type":         "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
					"remoteIp":      "41.82.183.143",
					"statusDetails": "response_sent_by_backend",
				},
				SpanID:  "7a91e0b25edf30e0",
				TraceID: "4ebc71f1def9274798cac4e8960d0095",
				Attributes: map[string]any{
					"gcp.log_name": "projects/wavemm-174408/logs/requests",
					"gcp.http_request": map[string]any{
						"latency":        "0.248406s",
						"remote_ip":      "41.82.183.143",
						"request_method": "POST",
						"request_size":   522,
						"request_url":    "https://sn.mmapp.wave.com/graphql",
						"response_size":  1750,
						"server_ip":      "10.56.35.14",
						"status":         200,
						"user_agent":     "com.wave.personal/23040401(Linux;U;Android10;fr_SN;OrangeNolafun;Build/QP1A.190711.020;Cronet/111.0.5563.55)",
					},
					"gcp.receive_timestamp": "2023-04-21T15:59:26.407178441Z",
					"gcp.insert_id":         "mr6p8jfcxlde5",
				},
			},
		},
		// 		{input:`{
		//   "httpRequest": {
		//     "latency": "0.120593s",
		//     "remoteIp": "41.82.128.67",
		//     "requestMethod": "POST",
		//     "requestSize": "430",
		//     "requestUrl": "https://sn.mmapp.wave.com/graphql",
		//     "responseSize": "61",
		//     "serverIp": "10.56.1.17",
		//     "status": 200,
		//     "userAgent": "com.wave.personal/23040401(Linux;U;Android13;fr_FR;SM-T225N;Build/TP1A.220624.014;Cronet/111.0.5563.55)"
		//   },
		//   "insertId": "1n453wif2tky4i",
		//   "jsonPayload": {
		//     "@type": "type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
		//     "cacheDecision": [
		//       "RESPONSE_HAS_CONTENT_TYPE",
		//       "REQUEST_HAS_AUTHORIZATION",
		//       "CACHE_MODE_USE_ORIGIN_HEADERS"
		//     ],
		//     "remoteIp": "41.82.128.67",
		//     "statusDetails": "response_sent_by_backend"
		//   },
		//   "logName": "projects/wavemm-174408/logs/requests",
		//   "receiveTimestamp": "2023-04-21T15:59:26.437769664Z",
		//   "resource": {
		//     "labels": {
		//       "backend_service_name": "k8s1-14266937-default-app-aware-reverse-proxy-serv-808-161f7c20",
		//       "forwarding_rule_name": "k8s-fws-default-money-srv-web-ingress--142669370e5711a1",
		//       "project_id": "wavemm-174408",
		//       "target_proxy_name": "k8s-tps-default-money-srv-web-ingress--142669370e5711a1",
		//       "url_map_name": "k8s-um-default-money-srv-web-ingress--142669370e5711a1",
		//       "zone": "global"
		//     },
		//     "type": "http_load_balancer"
		//   },
		//   "severity": "INFO",
		//   "spanId": "7f0dcb0321eb9216",
		//   "timestamp": "2023-04-21T15:59:25.726018Z",
		//   "trace": "projects/wavemm-174408/traces/6705a05ed252d3510aaf1b687abf2825"
		// }
		// `, want: Log{}},
	}

	logger, _ := zap.NewDevelopment()

	for _, tt := range tests {
		var errs error
		wantRes, wantLr, err := generateLog(tt.want)
		errs = multierr.Append(errs, err)

		gotRes, gotLr, err := TranslateLogEntry(context.TODO(), logger, []byte(tt.input))
		errs = multierr.Append(errs, err)
		errs = multierr.Combine(errs, compareResources(wantRes, gotRes), compareLogRecords(wantLr, gotLr))

		require.NoError(t, errs)
	}
}

func compareResources(expected, actual pcommon.Resource) error {
	return compare("Resource.Attributes", expected.Attributes().AsRaw(), actual.Attributes().AsRaw())
}

func compareLogRecords(expected, actual plog.LogRecord) error {
	return multierr.Combine(
		compare("LogRecord.Timestamp", expected.Timestamp(), actual.Timestamp()),
		compare("LogRecord.Attributes", expected.Attributes().AsRaw(), actual.Attributes().AsRaw()),
		compare("LogRecord.Body", expected.Body().AsRaw(), actual.Body().AsRaw()),
	)
}

func compare(ty string, expected, actual any, opts ...cmp.Option) error {
	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		return fmt.Errorf("%s mismatch (-expected +actual):\n%s", ty, diff)
	}
	return nil
}
