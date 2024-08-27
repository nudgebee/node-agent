package tracing

import (
	"context"
	"fmt"
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
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	MemcacheDBItemKeyName attribute.Key = "db.memcached.item"
)

var (
	tracer           func(containerId string) trace.Tracer
	instanceMetadata *metadata.CloudMetadata
)

func Init(machineId, hostname, version string) {
	md := metadata.GetInstanceMetadata()
	endpointUrl := *flags.TracesEndpoint
	instanceMetadata = md
	if endpointUrl == nil {
		klog.Infoln("no OpenTelemetry traces collector endpoint configured")
		return
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
	}
	if endpointUrl.Scheme != "https" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	client := otlptracehttp.NewClient(opts...)
	exporter, err := otlptrace.New(context.Background(), client)
	if err != nil {
		klog.Exitln(err)
	}

	batcher := sdktrace.WithBatcher(exporter)

	// if md is nil
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
	tracer = func(containerId string) trace.Tracer {
		provider := sdktrace.NewTracerProvider(
			batcher,
			sdktrace.WithResource(resource.NewWithAttributes(
				semconv.SchemaURL,
				semconv.HostName(hostname),
				semconv.HostID(machineId),
				semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
				semconv.ContainerID(containerId),
				semconv.CloudAccountID(accountId),
				semconv.CloudRegion(region),
				semconv.CloudAvailabilityZone(availabilityZone),
			)),
		)
		return provider.Tracer("nudgebee-node-agent", trace.WithInstrumentationVersion(version))
	}
}

type Trace struct {
	containerId string
	destination netaddr.IPPort
	commonAttrs []attribute.KeyValue
}

func NewTrace(containerId string, destination netaddr.IPPort, srcWorkload common.Workload, dstWorkload common.Workload, actualDstWorkload common.Workload) *Trace {
	if tracer == nil {
		return nil
	}
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

	return &Trace{containerId: containerId, destination: destination, commonAttrs: []attribute.KeyValue{
		semconv.NetPeerName(destination.IP().String()),
		semconv.NetPeerPort(int(destination.Port())),
		attribute.Key("destination.workload_name").String(dstWorkload.Name),
		attribute.Key("destination.workload_namespace").String(dstWorkload.Namespace),
		attribute.Key("destination.workload_kind").String(dstWorkload.Kind),
		attribute.Key("source.workload_name").String(srcWorkload.Name),
		attribute.Key("source.workload_namespace").String(srcWorkload.Namespace),
		attribute.Key("source.workload_kind").String(srcWorkload.Kind),
		attribute.Key("destination.name").String(actualDstWorkload.Name),
		attribute.Key("destination.namespace").String(actualDstWorkload.Namespace),
		attribute.Key("destination.kind").String(actualDstWorkload.Kind),
		attribute.Key("destination.cloud.availablity_zone").String(zone),
		attribute.Key("destination.cloud.region").String(region),
		attribute.Key("destination.node").String(node),
	}}
}

func (t *Trace) createSpan(name string, duration time.Duration, error bool, attrs ...attribute.KeyValue) {
	end := time.Now()
	start := end.Add(-duration)
	_, span := tracer(t.containerId).Start(nil, name, trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(attrs...)
	span.SetAttributes(t.commonAttrs...)
	if error {
		span.SetStatus(codes.Error, "")
	}
	span.End(trace.WithTimestamp(end))
}

func (t *Trace) HttpRequest(method, path string, status l7.Status, duration time.Duration, requestSize uint64, payload string, headers string, response string, host string, destWorkload common.Workload) {
	if t == nil || method == "" {
		return
	}
	if host == "" {
		host = t.destination.String()
	}
	requestPayload := ""
	if utf8.ValidString(payload) {
		requestPayload = payload
	}
	requestHeaders := ""
	if utf8.ValidString(headers) {
		requestHeaders = headers
	}
	responsePayload := ""
	if utf8.ValidString(response) {
		responsePayload = response
	}
	requestPath := ""
	if utf8.ValidString(path) {
		requestPath = path
	}
	t.createSpan(method, duration, status >= 400,
		semconv.HTTPURL(fmt.Sprintf("http://%s%s", host, requestPath)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
		semconv.HTTPRequestContentLength(int(requestSize)),
		attribute.Key("http.request_payload").String(requestPayload),
		attribute.Key("http.headers").String(requestHeaders),
		attribute.Key("http.response").String(responsePayload),
		attribute.Key("http.path").String(requestPath),
	)
}

func (t *Trace) Http2Request(method, path, scheme string, status l7.Status, duration time.Duration, payload string) {
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
	t.createSpan(method, duration, status > 400,
		semconv.HTTPURL(fmt.Sprintf("%s://%s%s", scheme, t.destination.String(), path)),
		semconv.HTTPMethod(method),
		semconv.HTTPStatusCode(int(status)),
		attribute.Key("http.request_payload").String(payload),
	)
}

func (t *Trace) PostgresQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemPostgreSQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MysqlQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
		semconv.DBSystemMySQL,
		semconv.DBStatement(query),
	)
}

func (t *Trace) MongoQuery(query string, error bool, duration time.Duration) {
	if t == nil || query == "" {
		return
	}
	t.createSpan("query", duration, error,
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
	t.createSpan(cmd, duration, error, attrs...)
}

func (t *Trace) RedisQuery(cmd, args string, error bool, duration time.Duration) {
	if t == nil || cmd == "" {
		return
	}
	statement := cmd
	if args != "" {
		statement += " " + args
	}
	t.createSpan(cmd, duration, error,
		semconv.DBSystemRedis,
		semconv.DBOperation(cmd),
		semconv.DBStatement(statement),
	)
}
