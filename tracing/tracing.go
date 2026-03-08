package tracing

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

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
	return strings.ToValidUTF8(s, "�")
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
	if duration <= 0 || duration > time.Hour {
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

	// Use destination hostname for external services, fallback to provided host
	requestHost := sanitizeUTF8(host)
	if host == "" || isIPAddress(host) {
		// Use destination hostname if host is empty or an IP address
		if t.destination.Port() != 0 {
			requestHost = sanitizeUTF8(t.destination.String())
		}
	}

	requestPayload := sanitizeUTF8(payload)
	requestHeaders := ""
	responsePayload := sanitizeUTF8(response)
	requestPath := sanitizeUTF8(path)

	if headers != nil {
		requestHeaders = sanitizeUTF8(l7.ConvertHeadersToBase64String(headers))
	}

	// Determine protocol based on port or known LLM APIs
	protocol := "http"
	if isHTTPSService(requestHost) || t.destination.Port() == 443 {
		protocol = "https"
	}

	traceId := sanitizeUTF8(t.ExtractTraceId(headers))
	t.createSpan(sanitizeUTF8(method), duration, status >= 400,
		traceId,
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", protocol, requestHost, requestPath)),
		semconv.HTTPMethod(sanitizeUTF8(method)),
		semconv.HTTPStatusCode(int(status)),
		semconv.HTTPRequestContentLength(int(requestSize)),
		attribute.Key("http.request_payload").String(sanitizeUTF8(requestPayload)),
		attribute.Key("http.headers").String(sanitizeUTF8(requestHeaders)),
		attribute.Key("http.response").String(sanitizeUTF8(responsePayload)),
		attribute.Key("http.path").String(sanitizeUTF8(requestPath)),
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
		semconv.DBStatement(sanitizeUTF8(query)),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemMySQL,
		semconv.DBStatement(sanitizeUTF8(query)),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemMongoDB,
		semconv.DBStatement(sanitizeUTF8(query)),
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
		attrs = append(attrs, MemcacheDBItemKeyName.String(sanitizeUTF8(items[0])))
	} else if len(items) > 1 {
		sanitizedItems := make([]string, len(items))
		for i, item := range items {
			sanitizedItems[i] = sanitizeUTF8(item)
		}
		attrs = append(attrs, MemcacheDBItemKeyName.StringSlice(sanitizedItems))
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
		semconv.DBOperation(sanitizeUTF8(cmd)),
		semconv.DBStatement(sanitizeUTF8(statement)),
	)
}

func (t *Trace) ClickhouseQuery(query string, error bool, duration time.Duration) {
	if t == nil {
		return
	}
	t.createSpan("query", duration, error, "",
		semconv.DBSystemClickhouse,
		semconv.DBStatement(sanitizeUTF8(query)),
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
		semconv.DBStatementKey.String(sanitizeUTF8(statement)),
		attribute.Key("zookeeper.status_code").Int(int(status)),
	)
}

// isIPAddress checks if a string is an IP address
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// isHTTPSService checks if a hostname is known to use HTTPS
func isHTTPSService(host string) bool {
	// Common LLM API services that use HTTPS
	httpsServices := []string{
		"api.openai.com",
		"api.anthropic.com",
		"api.cohere.ai",
		"api.cohere.com",
		"generativelanguage.googleapis.com",
		"ai.googleapis.com",
		"aiplatform.googleapis.com",
		"claude.ai",
	}

	hostLower := strings.ToLower(host)
	for _, service := range httpsServices {
		if strings.Contains(hostLower, service) {
			return true
		}
	}

	return false
}

// LLMStreamInfo contains information about a completed LLM stream for tracing
type LLMStreamInfo struct {
	Provider         string
	Model            string
	Operation        string
	ServerAddress    string
	TraceID          string
	ParentSpanID     string
	RequestTime      time.Time
	FirstTokenTime   time.Time
	CompletionTime   time.Time
	InputTokens      int
	OutputTokens     int
	StatusCode       int
	IsError          bool
	CompletionReason string
}

// LLMRequest creates a trace span for an LLM API request
func (t *Trace) LLMRequest(info LLMStreamInfo) {
	if t == nil || t.tracer.otel == nil {
		return
	}
	if info.RequestTime.IsZero() || info.CompletionTime.IsZero() || !info.CompletionTime.After(info.RequestTime) {
		return
	}
	if info.CompletionTime.Sub(info.RequestTime) > time.Hour {
		return
	}

	if !shouldSample() {
		return
	}

	ctx := context.Background()

	// Set up parent context from traceparent if available
	if info.TraceID != "" {
		traceID, err := trace.TraceIDFromHex(info.TraceID)
		if err == nil {
			spanCtxConfig := trace.SpanContextConfig{
				TraceID:    traceID,
				TraceFlags: trace.FlagsSampled,
				Remote:     true,
			}
			if info.ParentSpanID != "" {
				spanID, err := trace.SpanIDFromHex(info.ParentSpanID)
				if err == nil {
					spanCtxConfig.SpanID = spanID
				}
			}
			spanCtx := trace.NewSpanContext(spanCtxConfig)
			ctx = trace.ContextWithRemoteSpanContext(ctx, spanCtx)
		}
	}

	// Span name follows OTel GenAI conventions: "{provider} {operation}"
	spanName := fmt.Sprintf("%s %s", sanitizeUTF8(info.Provider), sanitizeUTF8(info.Operation))

	// Create span with explicit start time
	_, span := t.tracer.otel.Start(ctx, spanName,
		trace.WithTimestamp(info.RequestTime),
		trace.WithSpanKind(trace.SpanKindClient),
	)

	// OTel GenAI semantic conventions attributes
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.system", sanitizeUTF8(info.Provider)),
		attribute.String("gen_ai.operation.name", sanitizeUTF8(info.Operation)),
		attribute.String("gen_ai.request.model", sanitizeUTF8(info.Model)),
		attribute.String("server.address", sanitizeUTF8(info.ServerAddress)),
		attribute.Int("server.port", 443),
		attribute.String("network.protocol.name", "http"),
		attribute.String("network.protocol.version", "2"),
		attribute.Bool("gen_ai.response.is_streaming", true),
	}

	// Token usage
	if info.InputTokens > 0 {
		attrs = append(attrs, attribute.Int("gen_ai.usage.input_tokens", info.InputTokens))
	}
	if info.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int("gen_ai.usage.output_tokens", info.OutputTokens))
	}
	if info.InputTokens > 0 || info.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int("gen_ai.usage.total_tokens", info.InputTokens+info.OutputTokens))
	}

	// TTFT (Time to First Token)
	if !info.FirstTokenTime.IsZero() {
		ttftMs := info.FirstTokenTime.Sub(info.RequestTime).Milliseconds()
		attrs = append(attrs, attribute.Int64("gen_ai.response.time_to_first_token_ms", ttftMs))

		// Add first token event
		span.AddEvent("gen_ai.first_token",
			trace.WithTimestamp(info.FirstTokenTime),
			trace.WithAttributes(
				attribute.Int64("gen_ai.response.time_to_first_token_ms", ttftMs),
			),
		)
	}

	// Tokens per second
	if info.OutputTokens > 0 && !info.FirstTokenTime.IsZero() && !info.CompletionTime.IsZero() {
		genDuration := info.CompletionTime.Sub(info.FirstTokenTime).Seconds()
		if genDuration > 0 {
			tps := float64(info.OutputTokens) / genDuration
			attrs = append(attrs, attribute.Float64("gen_ai.response.tokens_per_second", tps))
		}
	}

	// HTTP status code
	if info.StatusCode > 0 {
		attrs = append(attrs, attribute.Int("http.response.status_code", info.StatusCode))
	}

	// Set all attributes
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)

	// Stream completion event
	span.AddEvent("gen_ai.stream_complete",
		trace.WithTimestamp(info.CompletionTime),
		trace.WithAttributes(
			attribute.Int("gen_ai.usage.output_tokens", info.OutputTokens),
			attribute.String("gen_ai.completion_reason", sanitizeUTF8(info.CompletionReason)),
		),
	)

	// Set error status if applicable
	if info.IsError {
		errorType := "unknown"
		switch info.StatusCode {
		case 429:
			errorType = "rate_limit"
		case 400, 422:
			errorType = "invalid_request"
		case 401, 403:
			errorType = "auth_error"
		case 500, 502, 503, 504:
			errorType = "server_error"
		}
		span.SetStatus(codes.Error, errorType)
		span.SetAttributes(attribute.String("error.type", errorType))
	}

	// End span with completion time
	span.End(trace.WithTimestamp(info.CompletionTime))
}
