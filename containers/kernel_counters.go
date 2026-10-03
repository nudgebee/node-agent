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
// protocol data), LLM capture chunks and L7 events lost to a full ring buffer,
// and TLS plaintext the hooks could not attribute to a socket.
var llmCaptureDropsDesc = prometheus.NewDesc(
	"node_agent_llm_capture_drops_total",
	"LLM capture chunks lost in the kernel because the L7 ring buffer was full",
	nil, nil,
)

var tlsPlaintextDroppedDesc = prometheus.NewDesc(
	"node_agent_tls_plaintext_dropped_total",
	"TLS plaintext seen by a library hook in the kernel but not attributed to a socket, so never captured, by reason",
	[]string{"reason"}, nil,
)

var l7RingbufDropsDesc = prometheus.NewDesc(
	"node_agent_l7_ringbuf_drops_total",
	"L7 events lost in the kernel because the L7 ring buffer was full",
	nil, nil,
)

type kernelCounterCollector struct {
	tracer *ebpftracer.Tracer
}

func (c kernelCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsCiphertextSkippedDesc
	ch <- llmCaptureDropsDesc
	ch <- tlsPlaintextDroppedDesc
	ch <- l7RingbufDropsDesc
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
	if dropped, ok := c.tracer.TLSPlaintextDropped(); ok {
		for reason, v := range dropped {
			ch <- prometheus.MustNewConstMetric(tlsPlaintextDroppedDesc, prometheus.CounterValue, float64(v), reason)
		}
	}
	if drops, ok := c.tracer.L7RingbufDrops(); ok {
		ch <- prometheus.MustNewConstMetric(l7RingbufDropsDesc, prometheus.CounterValue, float64(drops))
	}
}
