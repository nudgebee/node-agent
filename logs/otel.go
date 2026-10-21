package logs

import (
	"context"
	"encoding/binary"
	"net/url"
	"slices"
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

var (
	otelLogger otelLogs.Logger
	retrying   *retryingExporter
	// nodeName is set on every Kubernetes container's records as k8s.node.name.
	nodeName string
)

// ownerRefresh is how long a container's records reuse its pod's resolved owner.
// The owner can resolve late: a pod the resolver has not indexed yet is looked up
// through the API server, which reports it as the pod itself (kind pod) when that
// call fails, and a CronJob's pod whose Job is not cached yet resolves to the Job.
// So the owner is looked up again rather than kept for the container's lifetime.
const ownerRefresh = time.Minute

// K8sContainer labels a Kubernetes container's records with the attributes log
// queries filter on: k8s.namespace.name, k8s.pod.name, k8s.container.name,
// k8s.node.name and the top-level owner's k8s.<kind>.name.
type K8sContainer struct {
	Namespace string
	Pod       string
	Container string
	// Owner resolves the pod's top-level owner; nil means none is known.
	Owner func() common.Workload

	owner   common.Workload
	ownerAt time.Time
	res     *resource.Resource
}

// ownerAttrKeys are the owner kinds with a semantic-convention attribute that log
// queries read as the workload. Any other owner (ReplicaSet, Rollout, a bare pod)
// sets none, and queries fall back to the pod name. So does a Job: the resolver
// reports a standalone Job (AGGREGATE_EPHEMERAL_WORKLOADS) under an aggregated
// name, which k8s.job.name must not carry.
var ownerAttrKeys = map[string]attribute.Key{
	"Deployment":  semconv.K8SDeploymentNameKey,
	"StatefulSet": semconv.K8SStatefulSetNameKey,
	"DaemonSet":   semconv.K8SDaemonSetNameKey,
	"CronJob":     semconv.K8SCronJobNameKey,
}

// resource is the resource of a record emitted at now: base plus the Kubernetes
// attributes. It is built once, and again only when the pod's resolved owner changes.
// Called from the container's parser goroutine only.
func (k *K8sContainer) resource(base []attribute.KeyValue, now time.Time) *resource.Resource {
	if k.Owner != nil && now.Sub(k.ownerAt) >= ownerRefresh {
		if owner := k.Owner(); owner != k.owner {
			k.owner, k.res = owner, nil
		}
		k.ownerAt = now
	}
	if k.res != nil {
		return k.res
	}
	attrs := append(slices.Clip(base),
		semconv.K8SNamespaceName(k.Namespace),
		semconv.K8SPodName(k.Pod),
		semconv.K8SContainerName(k.Container),
	)
	if nodeName != "" {
		attrs = append(attrs, semconv.K8SNodeName(nodeName))
	}
	if key, ok := ownerAttrKeys[k.owner.Kind]; ok && k.owner.Name != "" {
		attrs = append(attrs, key.String(k.owner.Name))
	}
	k.res = resource.NewSchemaless(attrs...)
	return k.res
}

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
	nodeName = *flags.NodeName
	if nodeName == "" {
		nodeName = hostname
	}
	if file := *flags.LogsPositionsFile; file != "" {
		p, err := loadPositions(file, *flags.LogsMaxPositionAge)
		if err != nil {
			klog.Warningln(err)
		}
		if p != nil {
			savedPositions = p
			klog.Infoln("log positions file:", file)
			go savePositionsEvery(positionsSaveInterval)
		}
	}
	loggerProvider := startDelivery(newExporter(endpointUrl), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("nudgebee-node-agent"),
		semconv.HostName(hostname),
		semconv.HostID(machineId),
	))
	otel.SetLoggerProvider(loggerProvider)
	otelLogger = loggerProvider.Logger("nudgebee-node-agent", otelLogs.WithInstrumentationVersion(version))
}

// newExporter sends records to the OTLP/HTTP logs endpoint u.
func newExporter(u *url.URL) sdk.LogRecordExporter {
	path := u.Path
	if path == "" {
		path = "/"
	}
	opts := []otlplogshttp.Option{
		otlplogshttp.WithEndpoint(u.Host),
		otlplogshttp.WithURLPath(path),
		otlplogshttp.WithHeaders(common.AuthHeaders()),
		// The exporter sends each record with its own copy of its container's
		// resource, which compresses well.
		otlplogshttp.WithCompression(otlplogshttp.GzipCompression),
		// 429 and 503 (the collector shedding load) are retried for as long as they last.
		otlplogshttp.WithRetry(otlplogshttp.RetryConfig{
			Enabled:         true,
			InitialInterval: time.Second,
			MaxInterval:     maxRetryInterval,
			MaxElapsedTime:  0,
		}),
	}
	if u.Scheme != "https" {
		opts = append(opts, otlplogshttp.WithInsecure())
	} else {
		opts = append(opts, otlplogshttp.WithTLSClientConfig(common.TlsConfig()))
	}
	exporter, _ := otlplogs.NewExporter(context.Background(), otlplogs.WithClient(otlplogshttp.NewClient(opts...)))
	return exporter
}

// startDelivery tracks the delivery of every record exported through exporter (see
// delivery) and returns the provider to emit them with.
func startDelivery(exporter sdk.LogRecordExporter, res *resource.Resource) *sdk.LoggerProvider {
	dlv = newDelivery()
	retrying = newRetryingExporter(exporter, dlv)
	return sdk.NewLoggerProvider(
		sdk.WithBatcher(retrying,
			sdk.WithMaxQueueSize(queueSize),
			sdk.WithBlocking(),
			// retrying retries until delivered; Shutdown stops it.
			sdk.WithExportTimeout(0),
		),
		sdk.WithResource(res),
	)
}

const positionsSaveInterval = 10 * time.Second

func savePositionsEvery(interval time.Duration) {
	for range time.Tick(interval) {
		if err := savedPositions.save(); err != nil {
			klog.Warningln("failed to save log positions:", err)
		}
	}
}

// flushGrace lets every parser pass on the message it is still collecting once its
// reader stops: a multiline message is passed on 1-2 s after its last line, and a
// split line's parts are joined for up to as long again. Anything still held after
// it is read again on the next start.
var flushGrace = 4 * time.Second

// Shutdown stops reading log files, waits up to timeout for the records already
// read to be delivered, and saves how far each file was delivered. Lines read but
// not delivered by then are read again on the next start.
func Shutdown(timeout time.Duration) {
	if dlv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	dlv.stopReading()
	select {
	case <-time.After(flushGrace):
	case <-ctx.Done():
	}
	if dlv.drain(ctx) {
		klog.Infof("delivered all read log records in %s", time.Since(start).Round(time.Millisecond))
	} else {
		klog.Warningf("%d log records were not delivered within %s; their lines are read again on the next start", dlv.pendingCount(), timeout)
	}
	if err := savedPositions.save(); err != nil {
		klog.Warningln("failed to save log positions:", err)
	}
	retrying.stop()
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

// logIostreamKey is the semantic-convention record attribute for the stream a line
// was written to ("stdout" / "stderr").
const logIostreamKey = attribute.Key("log.iostream")

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

// OtelLogEmitter exports a container's messages. A record's time is the line's own
// (the container runtime's, when the source records it); ObservedTimestamp is when
// the agent emits it, at most a multiline timeout or so after reading it. k8s labels
// a Kubernetes container's records; nil for others. src is the file the messages are
// read from, whose position advances as their records are delivered; nil for other
// sources (journald).
func OtelLogEmitter(containerId string, k8s *K8sContainer, src *Source) logparser.OnMsgCallbackF {
	if otelLogger == nil {
		return nil
	}
	base := []attribute.KeyValue{
		semconv.ServiceName(common.ContainerIdToOtelServiceName(containerId)),
		semconv.ContainerID(containerId),
	}
	// Outside Kubernetes, every record has the same resource.
	res := resource.NewSchemaless(base...)
	return func(ts time.Time, level logparser.Level, patternHash string, msg string, attributes map[string]string, stream string, offset int64) {
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
		if stream != "" {
			// The runtime's stream replaces a parsed field of the same name, since a
			// duplicate key would leave either one read.
			attrs = slices.DeleteFunc(attrs, func(a attribute.KeyValue) bool { return a.Key == logIostreamKey })
			attrs = append(attrs, logIostreamKey.String(stream))
		}

		now := time.Now()
		if k8s != nil {
			res = k8s.resource(base, now)
		}

		record := otelLogs.NewLogRecord(otelLogs.LogRecordConfig{
			Timestamp:         &ts,
			ObservedTimestamp: now,
			TraceId:           traceId,
			SpanId:            spanId,
			SeverityText:      &severityText,
			SeverityNumber:    &severityNumber,
			Body:              &msg,
			Resource:          res, // schemaless, so merging it into the provider's never fails and drops the record
			Attributes:        &attrs,
		})
		if dlv == nil {
			otelLogger.Emit(record)
			return
		}
		dlv.emit(src, offset, len(msg), func() { otelLogger.Emit(record) })
	}
}
