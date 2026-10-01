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

// tlsSkipCollector exports the kernel's per-CPU count of ciphertext events it
// declined to parse. Before the kernel made that distinction, every one of
// these reached the L7 parsers as if it were protocol data.
type tlsSkipCollector struct {
	tracer *ebpftracer.Tracer
}

func (c tlsSkipCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsCiphertextSkippedDesc
}

func (c tlsSkipCollector) Collect(ch chan<- prometheus.Metric) {
	writes, reads, ok := c.tracer.TLSCiphertextSkipped()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(tlsCiphertextSkippedDesc, prometheus.CounterValue, float64(writes), "write")
	ch <- prometheus.MustNewConstMetric(tlsCiphertextSkippedDesc, prometheus.CounterValue, float64(reads), "read")
}
