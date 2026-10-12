package logs

import (
	"context"
	"encoding/binary"
	"strconv"
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
	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
)

var otelLogger otelLogs.Logger

// PatternExtractionRateLimiter caps, per log source, how many warning and
// error messages per second get a log pattern extracted (nil: unlimited).
func PatternExtractionRateLimiter() *rate.Limiter {
	limit := *flags.LogPatternExtractionLimit
	if limit <= 0 {
		return nil
	}
	// At least 1: with a burst of 0 the limiter rejects every event, so a
	// limit below 0.1/s would turn pattern extraction off entirely.
	return rate.NewLimiter(rate.Limit(limit), max(1, int(limit*10)))
}

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

const patternHashKey = "pattern.hash"

func logRecordAttrs(patternHash string, attributes map[string]string) ([]attribute.KeyValue, *trace.TraceID, *trace.SpanID) {
	var traceId *trace.TraceID
	var spanId *trace.SpanID
	var spanIdAttr string
	attrs := make([]attribute.KeyValue, 0, len(attributes)+1)
	attrs = append(attrs, attribute.Key(patternHashKey).String(patternHash))
	for k, v := range attributes {
		if k == patternHashKey { // the agent's own; a duplicate key would hide it
			continue
		}
		switch normalizeTraceContextKey(k) {
		case traceIdKey:
			if traceId == nil {
				if id, ok := parseTraceId(k, v); ok {
					traceId = &id
					continue
				}
			}
		case spanIdKey:
			if spanId == nil {
				if id, ok := parseSpanId(k, v); ok {
					spanId, spanIdAttr = &id, k
					continue
				}
			}
		}
		attrs = append(attrs, attribute.Key(k).String(v))
	}
	if spanId != nil && traceId == nil { // a span id means nothing without its trace
		attrs = append(attrs, attribute.Key(spanIdAttr).String(attributes[spanIdAttr]))
		spanId = nil
	}
	return attrs, traceId, spanId
}

// parseTraceId parses a trace id. Datadog's log injection writes dd.trace_id
// as a decimal 64-bit number unless 128-bit ids are logged, as 32 hex
// characters; the decimal form is the lower half of the OpenTelemetry id.
func parseTraceId(k, v string) (trace.TraceID, bool) {
	if isDatadogKey(k) {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			var id trace.TraceID
			binary.BigEndian.PutUint64(id[8:], n)
			return id, n != 0
		}
	}
	id, err := trace.TraceIDFromHex(strings.ToLower(v))
	return id, err == nil
}

// parseSpanId parses a span id, which Datadog's log injection (dd.span_id)
// writes as a decimal number and everything else as hex.
func parseSpanId(k, v string) (trace.SpanID, bool) {
	if isDatadogKey(k) {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n == 0 {
			return trace.SpanID{}, false
		}
		var id trace.SpanID
		binary.BigEndian.PutUint64(id[:], n)
		return id, true
	}
	id, err := trace.SpanIDFromHex(strings.ToLower(v))
	return id, err == nil
}

func isDatadogKey(k string) bool {
	return strings.HasPrefix(strings.ToLower(k), "dd.")
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
