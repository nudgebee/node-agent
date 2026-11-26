package prom

import (
	"bytes"
	"compress/gzip"
	"io"
	"math"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/klog/v2"
)

// encodeOTLP builds a gzipped OTLP/HTTP request body.
//
// A store must end up with the same series as over remote write, because queries
// select by exact name and by `job` and `instance`. So names are sent as they are
// with no unit (stores derive suffixes from units), and `job` and `instance` are
// set on every data point (not every store derives them from service.*).
func encodeOTLP(mfs []*dto.MetricFamily, timestampMs int64, extraLabels map[string]string) ([]byte, error) {
	data, err := proto.Marshal(buildOTLPRequest(mfs, timestampMs, extraLabels))
	if err != nil {
		return nil, err
	}
	buf := &bytes.Buffer{}
	w := gzip.NewWriter(buf)
	if _, err = w.Write(data); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildOTLPRequest(mfs []*dto.MetricFamily, timestampMs int64, extraLabels map[string]string) *collectorpb.ExportMetricsServiceRequest {
	ts := uint64(timestampMs) * 1e6
	metrics := make([]*metricspb.Metric, 0, len(mfs))
	for _, mf := range mfs {
		if m := otlpMetric(mf, ts, extraLabels); m != nil {
			metrics = append(metrics, m)
		}
	}
	// No service.version and no instrumentation scope: VictoriaMetrics puts both on
	// every series, so each agent upgrade would start new ones. node_agent_info has
	// the version.
	resource := &resourcepb.Resource{Attributes: otlpAttributes(map[string]string{
		"service.name":        extraLabels[model.JobLabel],
		"service.instance.id": extraLabels[model.InstanceLabel],
	})}
	return &collectorpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource:     resource,
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: metrics}},
		}},
	}
}

func otlpMetric(mf *dto.MetricFamily, ts uint64, extraLabels map[string]string) *metricspb.Metric {
	var numbers []*metricspb.NumberDataPoint
	var histograms []*metricspb.HistogramDataPoint
	for _, m := range mf.Metric {
		attrs := otlpAttributes(otlpLabels(m, extraLabels))
		switch {
		case m.Gauge != nil:
			numbers = append(numbers, numberPoint(attrs, 0, ts, m.GetGauge().GetValue()))
		case m.Counter != nil:
			numbers = append(numbers, numberPoint(attrs, startTime(m.GetCounter().GetCreatedTimestamp()), ts, m.GetCounter().GetValue()))
		case m.Histogram != nil:
			histograms = append(histograms, histogramPoint(attrs, startTime(m.GetHistogram().GetCreatedTimestamp()), ts, m.GetHistogram()))
		}
	}

	res := &metricspb.Metric{Name: mf.GetName(), Description: mf.GetHelp()}
	switch {
	case len(histograms) > 0:
		res.Data = &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
			DataPoints:             histograms,
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
		}}
	case len(numbers) == 0:
		return nil
	// A store appends `_total` to a monotonic sum that lacks it, which would
	// rename the series. Such a counter goes as a gauge to keep its name.
	case mf.GetType() == dto.MetricType_COUNTER && strings.HasSuffix(mf.GetName(), "_total"):
		res.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
			DataPoints:             numbers,
			AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			IsMonotonic:            true,
		}}
	default:
		res.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: numbers}}
	}
	return res
}

// startTime is when a cumulative series began, or 0 (unknown) for one the agent
// only reads, such as a kernel or cgroup counter. The agent's own start time would
// be wrong for both: host counters outlive it, and a series can be deleted and
// recreated while it runs.
func startTime(created *timestamppb.Timestamp) uint64 {
	if created == nil {
		return 0
	}
	return uint64(created.AsTime().UnixNano())
}

// otlpLabels gives the metric's own labels precedence, as makeLabelsMap does for
// remote write. Empty values are dropped: Prometheus treats them as absent.
func otlpLabels(m *dto.Metric, extraLabels map[string]string) map[string]string {
	labels := make(map[string]string, len(m.Label)+len(extraLabels))
	for k, v := range extraLabels {
		labels[k] = v
	}
	for _, l := range m.Label {
		labels[l.GetName()] = l.GetValue()
	}
	for k, v := range labels {
		if v == "" {
			delete(labels, k)
		}
	}
	return labels
}

func otlpAttributes(labels map[string]string) []*commonpb.KeyValue {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	res := make([]*commonpb.KeyValue, 0, len(keys))
	for _, k := range keys {
		// protobuf refuses to marshal invalid UTF-8, which would lose the whole scrape.
		v := strings.ToValidUTF8(labels[k], "�")
		res = append(res, &commonpb.KeyValue{Key: k, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}}})
	}
	return res
}

func numberPoint(attrs []*commonpb.KeyValue, start, ts uint64, value float64) *metricspb.NumberDataPoint {
	return &metricspb.NumberDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: start,
		TimeUnixNano:      ts,
		Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
	}
}

// histogramPoint turns Prometheus cumulative buckets into OTLP per-bucket counts,
// whose last entry is the implicit +Inf bucket.
func histogramPoint(attrs []*commonpb.KeyValue, start, ts uint64, h *dto.Histogram) *metricspb.HistogramDataPoint {
	sum := h.GetSampleSum()
	p := &metricspb.HistogramDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: start,
		TimeUnixNano:      ts,
		Count:             h.GetSampleCount(),
		Sum:               &sum,
	}
	var previous uint64
	for _, b := range h.Bucket {
		if math.IsInf(b.GetUpperBound(), 1) {
			continue
		}
		p.ExplicitBounds = append(p.ExplicitBounds, b.GetUpperBound())
		p.BucketCounts = append(p.BucketCounts, b.GetCumulativeCount()-previous)
		previous = b.GetCumulativeCount()
	}
	p.BucketCounts = append(p.BucketCounts, h.GetSampleCount()-previous)
	return p
}

// logRejectedPoints reports data points a receiver refused while accepting the request.
func logRejectedPoints(body io.Reader) {
	data, err := io.ReadAll(io.LimitReader(body, 64*1024))
	if err != nil {
		return
	}
	res := &collectorpb.ExportMetricsServiceResponse{}
	if err = proto.Unmarshal(data, res); err != nil {
		return
	}
	if ps := res.GetPartialSuccess(); ps.GetRejectedDataPoints() > 0 {
		klog.Warningf("the receiver rejected %d data points: %s", ps.GetRejectedDataPoints(), ps.GetErrorMessage())
	}
}
