package tracing

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/node/metadata"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/klog/v2"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	// Remove invalid UTF-8 characters by converting to valid UTF-8
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		if r == utf8.RuneError {
			continue // Skip invalid runes
		}
		result.WriteRune(r)
	}

	return result.String()
}

var (
	batcher             sdktrace.TracerProviderOption
	commonResourceAttrs []attribute.KeyValue
	agentVersion        string
	initialized         bool
	samplingRate        float64
)

func Init(machineId, hostname, version string) {
	md := metadata.GetInstanceMetadata()
	endpointUrl := *flags.TracesEndpoint
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
	}

	samplingRate = *flags.TracesSampling
	if samplingRate < 0.0 || samplingRate > 1.0 {
		klog.Warningf("invalid traces-sampling value %f, must be between 0.0 and 1.0, using default 1.0", samplingRate)
		samplingRate = 1.0
	}
	if samplingRate < 1.0 {
		klog.Infof("trace sampling rate set to %f", samplingRate)
	}
	klog.Infoln("OpenTelemetry traces collector endpoint:", endpointUrl.String())
	path := endpointUrl.Path
	if path == "" {
		path = "/"
	}
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointUrl.Host),
		otlptracehttp.WithURLPath(path),
		otlptracehttp.WithHeaders(common.AuthHeaders()),
		otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify}),
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}

	batcher = sdktrace.WithBatcher(exporter)
	region := ""
	availabilityZone := ""
	accountId := ""
	if md == nil {
		region = *flags.Region
		availabilityZone = *flags.AvailabilityZone
		accountId = *flags.AccountId
		klog.Infoln("no cloud metadata available, using defaults")
	} else {
		region = md.Region
		availabilityZone = md.AvailabilityZone
		accountId = md.AccountId
	}
	commonResourceAttrs = []attribute.KeyValue{semconv.HostName(hostname), semconv.HostID(machineId),
		semconv.CloudAccountID(accountId),
		semconv.CloudRegion(region),
		semconv.CloudAvailabilityZone(availabilityZone)}

	if md == nil {
		region = *flags.Region
		availabilityZone = *flags.AvailabilityZone
		accountId = *flags.AccountId
		klog.Infoln("no cloud metadata available, using defaults")
	} else {
		region = md.Region
		availabilityZone = md.AvailabilityZone
		accountId = md.AccountId
	}
	agentVersion = version
	initialized = true
}

type Tracer struct {
	otel trace.Tracer
}

func shouldSample() bool {
	if samplingRate >= 1.0 {
		return true
	}
	if samplingRate <= 0.0 {
		return false
	}

	return rand.Float64() < samplingRate
}

func GetContainerTracer(containerId string) *Tracer {
	if !initialized {
		return &Tracer{otel: nil}
	}
	provider := sdktrace.NewTracerProvider(
		batcher,
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			append(
				commonResourceAttrs,
				semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
				semconv.ContainerID(containerId),
			)...,
		)),
	)
	return &Tracer{otel: provider.Tracer("nudgebee-node-agent", trace.WithInstrumentationVersion(agentVersion))}
}

func (t *Tracer) NewTrace(destination common.HostPort, srcWorkload common.Workload, dstWorkload common.Workload, actualDstWorkload common.Workload) *Trace {
	region := ""
	zone := ""
	node := ""
	if actualDstWorkload.Zone != "" {
		zone = actualDstWorkload.Zone
	}
	if actualDstWorkload.Region != "" {
		region = actualDstWorkload.Region
	}
	if actualDstWorkload.Instance != "" {
		node = actualDstWorkload.Instance
	}
	return &Trace{tracer: t, destination: destination, commonAttrs: []attribute.KeyValue{
		semconv.NetPeerName(sanitizeUTF8(destination.Host())),
		semconv.NetPeerPort(int(destination.Port())),
		attribute.Key("destination.workload_name").String(sanitizeUTF8(dstWorkload.Name)),
		attribute.Key("destination.workload_namespace").String(sanitizeUTF8(dstWorkload.Namespace)),
		attribute.Key("destination.workload_kind").String(sanitizeUTF8(dstWorkload.Kind)),
		attribute.Key("source.workload_name").String(sanitizeUTF8(srcWorkload.Name)),
		attribute.Key("source.workload_namespace").String(sanitizeUTF8(srcWorkload.Namespace)),
		attribute.Key("source.workload_kind").String(sanitizeUTF8(srcWorkload.Kind)),
		attribute.Key("destination.name").String(sanitizeUTF8(actualDstWorkload.Name)),
		attribute.Key("destination.namespace").String(sanitizeUTF8(actualDstWorkload.Namespace)),
		attribute.Key("destination.kind").String(sanitizeUTF8(actualDstWorkload.Kind)),
		attribute.Key("destination.cloud.availablity_zone").String(sanitizeUTF8(zone)),
		attribute.Key("destination.cloud.region").String(sanitizeUTF8(region)),
		attribute.Key("destination.node").String(sanitizeUTF8(node)),
	}}
}

type Trace struct {
	tracer      *Tracer
	destination common.HostPort
	commonAttrs []attribute.KeyValue
}

func (t *Trace) createSpan(name string, duration time.Duration, error bool, traceId string, attrs ...attribute.KeyValue) {
	if t.tracer.otel == nil {
		return
	}
	end := time.Now()

	if !shouldSample() {
		return
	}

	start := end.Add(-duration)
	ctx := context.Background()
	if traceId != "" {
		traceId = ParseTraceIdHeaders(traceId)
		traceID, err := trace.TraceIDFromHex(traceId)
		if err != nil {
			context.Background()
		}
		spanContext := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID,
		})
		ctx = trace.ContextWithRemoteSpanContext(ctx, spanContext)
	}

	_, span := t.tracer.otel.Start(ctx, name, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func ParseTraceIdHeaders(traceId string) string {
	if traceId == "" {
		return ""
	}
	// if its a traceparent header, extract the traceId
	parts := strings.Split(traceId, "-")
	if len(parts) == 4 {
		traceId = parts[1]
	}

	return traceId
}

func (t *Trace) ExtractTraceId(headers http.Header) string {
	if headers == nil {
		return ""
	}

	traceIdHeaders := strings.Split(*flags.TraceIdHeaders, ",")
	for _, header := range traceIdHeaders {
		if id := headers.Get(header); id != "" {
			return id
		} else if id := headers.Get(strings.ToLower(header)); id != "" {
			return id
		}
	}
	return ""
}

func (t *Trace) HttpRequest(method, path string, status l7.Status, duration time.Duration, requestSize uint64, payload string, headers http.Header, response string, host string) {
	if t == nil || method == "" {
		return
	}
	if host == "" {
		host = t.destination.String()
	}
	requestPayload := sanitizeUTF8(payload)
	requestHeaders := ""
	responsePayload := sanitizeUTF8(response)
	requestPath := sanitizeUTF8(path)
	requestHost := sanitizeUTF8(host)

	if headers != nil {
		requestHeaders = sanitizeUTF8(l7.ConvertHeadersToBase64String(headers))
	}

	traceId := sanitizeUTF8(t.ExtractTraceId(headers))
	t.createSpan(sanitizeUTF8(method), duration, status >= 400,
		traceId,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", requestHost, requestPath)),
		semconv.HTTPMethod(sanitizeUTF8(method)),
		semconv.HTTPStatusCode(int(status)),
		semconv.HTTPRequestContentLength(int(requestSize)),
		attribute.Key("http.request_payload").String(requestPayload),
		attribute.Key("http.headers").String(requestHeaders),
		attribute.Key("http.response").String(responsePayload),
		attribute.Key("http.path").String(requestPath),
	)
}

func (t *Trace) Http2Request(method, path, scheme string, status, grpcStatus l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if method == "" {
		method = "unknown"
	}
	if path == "" {
		path = "/unknown"
	}
	if scheme == "" {
		scheme = "unknown"
	}

	attrs := []attribute.KeyValue{
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
	}
	if grpcStatus >= 0 {
		attrs = append(attrs, semconv.RPCGRPCStatusCodeKey.Int(int(grpcStatus)))
	}
	t.createSpan(method, duration, status > 400 || grpcStatus > 0, "", attrs...)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemMongoDB,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MemcachedQuery(cmd string, items []string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemMemcached,
		semconv.DBOperation(cmd),
	}
	if len(items) == 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.String(items[0]))
	} else if len(items) > 1 {
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(items))
	}
	t.createSpan(cmd, duration, error, "", attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error, "",
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}

func (t *Trace) ClickhouseQuery(query string, error bool, duration time.Duration) {
	if t == nil {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemClickhouse,
		semconv.DBStatement(query),
	)
}

func (t *Trace) ZookeeperRequest(op string, args string, status l7.Status, duration time.Duration) {
	if t == nil {
		return
	}
	if op == "" {
		return
	}
	statement := op
	if args != "" {
		statement += " " + args
	}
	t.createSpan(op, duration, status.Zookeeper() != "ok", "",
		semconv.DBSystemKey.String("zookeeper"),
		semconv.DBOperation(op),
		semconv.DBStatementKey.String(statement),
		attribute.Key("zookeeper.status_code").Int(int(status)),
	)
}
