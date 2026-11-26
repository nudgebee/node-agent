package prom

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func decodeRequest(t *testing.T, payload []byte) *collectorpb.ExportMetricsServiceRequest {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(payload))
	require.NoError(t, err)
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	req := &collectorpb.ExportMetricsServiceRequest{}
	require.NoError(t, proto.Unmarshal(data, req))
	return req
}

func decodeOTLP(t *testing.T, payload []byte) map[string]*metricspb.Metric {
	t.Helper()
	req := decodeRequest(t, payload)
	res := map[string]*metricspb.Metric{}
	for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		res[m.Name] = m
	}
	return res
}

func attributeMap(kvs []*commonpb.KeyValue) map[string]string {
	res := map[string]string{}
	for _, kv := range kvs {
		res[kv.Key] = kv.Value.GetStringValue()
	}
	return res
}

func TestEncodeOTLP(t *testing.T) {
	reg := prometheus.NewRegistry()

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "node_info"}, []string{"hostname", "region"})
	gauge.WithLabelValues("web-1", "").Set(1)
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "node_resources_cpu_usage_seconds_total"}, []string{"mode"})
	counter.WithLabelValues("user").Add(12.5)
	unsuffixed := prometheus.NewCounter(prometheus.CounterOpts{Name: "container_jvm_gc_time_seconds"})
	unsuffixed.Add(3)
	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "container_http_requests_duration_seconds_total",
		Buckets: []float64{0.1, 1},
	})
	for _, v := range []float64{0.05, 0.5, 0.5, 5} {
		histogram.Observe(v)
	}
	reg.MustRegister(gauge, counter, unsuffixed, histogram)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	payload, err := encodeOTLP(mfs, 2000, map[string]string{"job": "nudgebee-node-agent", "instance": "abc"})
	require.NoError(t, err)
	metrics := decodeOTLP(t, payload)
	require.Len(t, metrics, 4)

	// Anything here that changes with the agent version becomes a new series on
	// every upgrade in stores that turn it into labels.
	rm := decodeRequest(t, payload).ResourceMetrics[0]
	assert.Equal(t, map[string]string{"service.name": "nudgebee-node-agent", "service.instance.id": "abc"}, attributeMap(rm.Resource.Attributes))
	assert.Nil(t, rm.ScopeMetrics[0].Scope)

	info := metrics["node_info"].GetGauge().GetDataPoints()
	require.Len(t, info, 1)
	assert.Equal(t, map[string]string{"job": "nudgebee-node-agent", "instance": "abc", "hostname": "web-1"}, attributeMap(info[0].Attributes))
	assert.Equal(t, uint64(2000*1e6), info[0].TimeUnixNano)

	cpu := metrics["node_resources_cpu_usage_seconds_total"].GetSum()
	require.NotNil(t, cpu)
	assert.True(t, cpu.IsMonotonic)
	assert.Equal(t, metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE, cpu.AggregationTemporality)
	assert.Equal(t, 12.5, cpu.DataPoints[0].GetAsDouble())
	assert.Equal(t, createdNano(t, mfs, "node_resources_cpu_usage_seconds_total"), cpu.DataPoints[0].StartTimeUnixNano)
	assert.Empty(t, metrics["node_resources_cpu_usage_seconds_total"].Unit)

	gc := metrics["container_jvm_gc_time_seconds"].GetGauge()
	require.NotNil(t, gc, "a counter without _total must not be a sum, or stores rename it")
	assert.Equal(t, 3.0, gc.DataPoints[0].GetAsDouble())

	latency := metrics["container_http_requests_duration_seconds_total"].GetHistogram()
	require.NotNil(t, latency)
	p := latency.DataPoints[0]
	assert.Equal(t, []float64{0.1, 1}, p.ExplicitBounds)
	assert.Equal(t, []uint64{1, 2, 1}, p.BucketCounts)
	assert.Equal(t, uint64(4), p.Count)
	assert.InDelta(t, 6.05, p.GetSum(), 1e-9)
}

func createdNano(t *testing.T, mfs []*dto.MetricFamily, name string) uint64 {
	t.Helper()
	for _, mf := range mfs {
		if mf.GetName() == name {
			created := mf.Metric[0].GetCounter().GetCreatedTimestamp()
			require.NotNil(t, created)
			return uint64(created.AsTime().UnixNano())
		}
	}
	t.Fatalf("no family %s", name)
	return 0
}

// A counter the agent only reads (kernel, cgroup) has no known start.
func TestEncodeOTLPConstCounterHasNoStartTime(t *testing.T) {
	desc := prometheus.NewDesc("node_net_received_bytes_total", "h", nil, nil)
	reg := prometheus.NewRegistry()
	reg.MustRegister(constCollector{prometheus.MustNewConstMetric(desc, prometheus.CounterValue, 7)})
	mfs, err := reg.Gather()
	require.NoError(t, err)

	payload, err := encodeOTLP(mfs, 2000, nil)
	require.NoError(t, err)
	p := decodeOTLP(t, payload)["node_net_received_bytes_total"].GetSum().DataPoints[0]
	assert.Zero(t, p.StartTimeUnixNano)
}

type constCollector struct{ m prometheus.Metric }

func (c constCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.m.Desc() }
func (c constCollector) Collect(ch chan<- prometheus.Metric) { ch <- c.m }

func TestEncodeOTLPInvalidUTF8(t *testing.T) {
	reg := prometheus.NewRegistry()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "up"})
	reg.MustRegister(gauge)
	mfs, err := reg.Gather()
	require.NoError(t, err)

	_, err = encodeOTLP(mfs, 1, map[string]string{"job": "j", "instance": "a\xff"})
	require.NoError(t, err)
}

func TestSpoolDirName(t *testing.T) {
	assert.NotEqual(t, spoolDirName(protocolPrometheus), spoolDirName(protocolOTLP))
	assert.Equal(t, "spool", spoolDirName(protocolPrometheus), "an upgrade must keep sending the existing spool")
}
