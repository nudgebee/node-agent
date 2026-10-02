package containers

import (
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/prometheus/client_golang/prometheus"
)

var tlsCiphertextSkippedDesc = prometheus.NewDesc(
	"node_agent_l7_tls_ciphertext_skipped_total",
	"Socket-level events dropped in the kernel because a TLS hook already delivers the connection's plaintext",
	[]string{"direction"}, nil,
)

// kernelCounterCollector exports counters the eBPF programs keep in per-CPU
// maps: socket-level ciphertext events skipped on TLS connections (before the
// kernel made that distinction, every one reached the L7 parsers as if it were
// protocol data), and LLM capture chunks lost to a full ring buffer.
var llmCaptureDropsDesc = prometheus.NewDesc(
	"node_agent_llm_capture_drops_total",
	"LLM capture chunks lost in the kernel because the L7 ring buffer was full",
	nil, nil,
)

type kernelCounterCollector struct {
	tracer *ebpftracer.Tracer
}

func (c kernelCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsCiphertextSkippedDesc
	ch <- llmCaptureDropsDesc
}

func (c kernelCounterCollector) Collect(ch chan<- prometheus.Metric) {
	writes, reads, ok := c.tracer.TLSCiphertextSkipped()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(tlsCiphertextSkippedDesc, prometheus.CounterValue, float64(writes), "write")
	ch <- prometheus.MustNewConstMetric(tlsCiphertextSkippedDesc, prometheus.CounterValue, float64(reads), "read")
	if drops, ok := c.tracer.LLMCaptureDrops(); ok {
		ch <- prometheus.MustNewConstMetric(llmCaptureDropsDesc, prometheus.CounterValue, float64(drops))
	}
}
