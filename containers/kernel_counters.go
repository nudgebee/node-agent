package containers

import (
	"strconv"

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
// TLS plaintext the hooks could not attribute to a socket, and how the Go TLS
// hooks found the sockets they did attribute. It also exports what the kernel
// gave the programs (node_agent_ebpf_info) and their sizes, so a capture gap
// on one cluster can be told apart from a bug.
var llmCaptureDropsDesc = prometheus.NewDesc(
	"node_agent_llm_capture_drops_total",
	"LLM capture chunks lost in the kernel because the L7 ring buffer was full",
	nil, nil,
)

var tlsPlaintextDroppedDesc = prometheus.NewDesc(
	"node_agent_tls_plaintext_dropped_total",
	"TLS plaintext seen by a library hook in the kernel but not attributed to a socket, so never captured, by reason. go_fd_unknown includes TLS over in-memory connections (net.Pipe, gRPC bufconn), which have no socket to capture",
	[]string{"reason"}, nil,
)

var l7RingbufDropsDesc = prometheus.NewDesc(
	"node_agent_l7_ringbuf_drops_total",
	"L7 events lost in the kernel because the L7 ring buffer was full",
	nil, nil,
)

var goTLSFdResolvedDesc = prometheus.NewDesc(
	"node_agent_go_tls_fd_resolved_total",
	"Go crypto/tls calls whose socket fd was found, by method and net.Conn wrapper depth. itab: the binary's *net.TCPConn itab; socket: a TCP netFD by its fields, confirmed as a TCP socket of that family by the kernel; shape: a TCP netFD by its fields only, as the kernel has no BTF to confirm it with",
	[]string{"method", "depth"}, nil,
)

var ebpfInfoDesc = prometheus.NewDesc(
	"node_agent_ebpf_info",
	"The eBPF program variant loaded for this kernel, whether the kernel's BTF loaded, and whether the socket struct offsets read from it were set. Without them sockets cannot be read from fds in the kernel, and Go TLS capture through wrapped connections rests on the shape check alone",
	[]string{"program_variant", "btf", "socket_offsets"}, nil,
)

var ebpfProgramInstructionsDesc = prometheus.NewDesc(
	"node_agent_ebpf_program_instructions",
	"Instructions in each loaded eBPF program after the kernel rewrote it",
	[]string{"program"}, nil,
)

var ebpfProgramVerifiedInstructionsDesc = prometheus.NewDesc(
	"node_agent_ebpf_program_verified_instructions",
	"Instructions the verifier processed to load each eBPF program, which its complexity limit applies to. Reported by kernels 5.16+",
	[]string{"program"}, nil,
)

type kernelCounterCollector struct {
	tracer *ebpftracer.Tracer
}

func (c kernelCounterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- tlsCiphertextSkippedDesc
	ch <- llmCaptureDropsDesc
	ch <- tlsPlaintextDroppedDesc
	ch <- l7RingbufDropsDesc
	ch <- goTLSFdResolvedDesc
	ch <- ebpfInfoDesc
	ch <- ebpfProgramInstructionsDesc
	ch <- ebpfProgramVerifiedInstructionsDesc
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
	if resolved, ok := c.tracer.GoTLSFdResolved(); ok {
		for _, r := range resolved {
			ch <- prometheus.MustNewConstMetric(goTLSFdResolvedDesc, prometheus.CounterValue, float64(r.Count), r.Method, strconv.Itoa(r.Depth))
		}
	}
	if info, ok := c.tracer.EBPFInfo(); ok {
		ch <- prometheus.MustNewConstMetric(ebpfInfoDesc, prometheus.GaugeValue, 1,
			info.ProgramVariant, strconv.FormatBool(info.KernelBTF), strconv.FormatBool(info.SocketOffsets))
		for _, p := range info.Programs {
			if p.Xlated > 0 {
				ch <- prometheus.MustNewConstMetric(ebpfProgramInstructionsDesc, prometheus.GaugeValue, float64(p.Xlated), p.Program)
			}
			if p.Verified > 0 {
				ch <- prometheus.MustNewConstMetric(ebpfProgramVerifiedInstructionsDesc, prometheus.GaugeValue, float64(p.Verified), p.Program)
			}
		}
	}
}
