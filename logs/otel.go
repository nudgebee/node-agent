package logs

import (
	"context"
	"strings"
	"time"

	otel "github.com/agoda-com/opentelemetry-logs-go"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs"
	"github.com/agoda-com/opentelemetry-logs-go/exporters/otlp/otlplogs/otlplogshttp"
	otelLogs "github.com/agoda-com/opentelemetry-logs-go/logs"
	sdk "github.com/agoda-com/opentelemetry-logs-go/sdk/logs"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/nudgebee/logparser"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/klog/v2"
)

var otelLogger otelLogs.Logger

func Init(machineId, hostname, version string) {
	endpointUrl := *flags.LogsEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry logs collector endpoint configured")
		return
	}
	klog.Infoln("OpenTelemetry logs collector endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}

	opts := []otlplogshttp.Option{
		otlplogshttp.WithEndpoint(endpointUrl.Host),
		otlplogshttp.WithURLPath(path),
		otlplogshttp.WithHeaders(common.AuthHeaders()),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlplogshttp.WithInsecure())
	} else {
		opts = append(opts, otlplogshttp.WithTLSClientConfig(common.TlsConfig()))
	}
	client := otlplogshttp.NewClient(opts...)
	exporter, _ := otlplogs.NewExporter(context.Background(), otlplogs.WithClient(client))

	loggerProvider := sdk.NewLoggerProvider(
		sdk.WithBatcher(exporter),
		sdk.WithResource(
			resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.ServiceName("nudgebee-node-agent"),
				semconv.HostName(hostname),
				semconv.HostID(machineId),
			),
		),
	)
	otel.SetLoggerProvider(loggerProvider)
	otelLogger = loggerProvider.Logger("nudgebee-node-agent", otelLogs.WithInstrumentationVersion(version))
}

const (
	traceIdKey = "traceid"
	spanIdKey  = "spanid"
)

var (
	traceIdKeys = []string{traceIdKey, "trace_id", "trace-id", "trace.id"}
	spanIdKeys  = []string{spanIdKey, "span_id", "span-id", "span.id"}
)

func normalizeTraceContextKey(k string) string {
	k = strings.ToLower(k)
	switch k {
	case "@tr":
		return traceIdKey
	case "@sp":
		return spanIdKey
	}
	if strings.Contains(k, "parent") { // e.g. parent_span_id is not the record's span id
		return ""
	}
	for _, s := range traceIdKeys {
		if k == s || strings.HasSuffix(k, "."+s) {
			return traceIdKey
		}
	}
	for _, s := range spanIdKeys {
		if k == s || strings.HasSuffix(k, "."+s) {
			return spanIdKey
		}
	}
	return ""
}

func logRecordAttrs(patternHash string, attributes map[string]string) ([]attribute.KeyValue, *trace.TraceID, *trace.SpanID) {
	var traceId *trace.TraceID
	var spanId *trace.SpanID
	attrs := make([]attribute.KeyValue, 0, len(attributes)+1)
	attrs = append(attrs, attribute.Key("pattern.hash").String(patternHash))
	for k, v := range attributes {
		switch normalizeTraceContextKey(k) {
		case traceIdKey:
			if traceId == nil {
				if id, err := trace.TraceIDFromHex(strings.ToLower(v)); err == nil {
					traceId = &id
					continue
				}
			}
		case spanIdKey:
			if spanId == nil {
				if id, err := trace.SpanIDFromHex(strings.ToLower(v)); err == nil {
					spanId = &id
					continue
				}
			}
		}
		attrs = append(attrs, attribute.Key(k).String(v))
	}
	return attrs, traceId, spanId
}

func OtelLogEmitter(containerId string) logparser.OnMsgCallbackF {
	if otelLogger == nil {
		return nil
	}
	return func(ts time.Time, level logparser.Level, patternHash string, msg string, attributes map[string]string) {
		severityText := level.String()
		severityNumber := otelLogs.UNSPECIFIED
		switch level {
		case logparser.LevelCritical:
			severityNumber = otelLogs.FATAL
		case logparser.LevelError:
			severityNumber = otelLogs.ERROR
		case logparser.LevelWarning:
			severityNumber = otelLogs.WARN
		case logparser.LevelInfo:
			severityNumber = otelLogs.INFO
		case logparser.LevelDebug:
			severityNumber = otelLogs.DEBUG
		}

		attrs, traceId, spanId := logRecordAttrs(patternHash, attributes)

		otelLogger.Emit(
			otelLogs.NewLogRecord(otelLogs.LogRecordConfig{
				ObservedTimestamp: ts,
				TraceId:           traceId,
				SpanId:            spanId,
				SeverityText:      &severityText,
				SeverityNumber:    &severityNumber,
				Body:              &msg,
				Resource: resource.NewSchemaless(
					semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
					semconv.ContainerID(containerId),
				),
				Attributes: &attrs,
			}),
		)
	}
}
