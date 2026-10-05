package containers

import (
	"net"
	"strconv"

	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

var (
	// HPACKDecodeErrorsTotal counts HPACK decode failures in the HTTP/2
	// parser: the decoder's dynamic table no longer matches the peer's, as
	// when the agent joined a long-lived connection mid-stream or missed a
	// HEADERS frame.
	HPACKDecodeErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "node_agent_hpack_decode_errors_total",
			Help: "Total HPACK decode errors in HTTP/2 parser (mid-stream join indicator)",
		},
	)

	// L7EventsTotal counts L7 events reaching userspace, and
	// L7PayloadTruncatedTotal counts the subset whose payload exceeded
	// MAX_PAYLOAD_SIZE and was therefore cut short in the kernel (the tail is
	// discarded, not delivered in a later event).
	//
	// The pair exists to make the truncation rate measurable per protocol and
	// per destination class. It matters most for HTTP/2: HPACK is stateful, so
	// a truncated frame cannot simply be skipped the way a truncated HTTP/1.1
	// request can. Compare
	//   rate(node_agent_l7_payload_truncated_total{protocol="http2",destination="external"}[5m])
	// against the same labels on node_agent_l7_events_total to see what share of
	// external HTTP/2 traffic is arriving incomplete.
	// direction is "client"/"server" for HTTP/2 (which frames the event carries)
	// and "-" for protocols where the distinction does not apply.
	//
	// External HTTP/2 delivers ~22,000 events per stream created, against ~105
	// internally. Splitting by direction separates the two explanations for
	// that: if server-frame events are scarce, responses never reach the parser;
	// if they are plentiful, the bytes being fed to it are not HTTP/2 at all and
	// the port-based detection heuristic is over-matching.
	L7EventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_l7_events_total",
			Help: "L7 events processed, by protocol, destination class, frame direction and whether the payload is TLS plaintext",
		},
		[]string{"protocol", "destination", "direction", "tls"},
	)

	L7PayloadTruncatedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_l7_payload_truncated_total",
			Help: "L7 events whose payload exceeded MAX_PAYLOAD_SIZE and was truncated in the kernel",
		},
		[]string{"protocol", "destination"},
	)

	// Http2ParserCapDropsTotal counts HTTP/2 events discarded because the
	// per-container parser map was already at maxHTTP2ParsersPerContainer.
	//
	// gc() only reclaims a parser whose connection is gone if the parser also
	// looks idle (no active requests, no partial data). A parser holding
	// requests that never completed therefore survives its connection
	// indefinitely, so a container with connection churn can fill the cap and
	// then silently drop every subsequent HTTP/2 connection. Non-zero here means
	// events are being lost before any parsing is attempted.
	Http2ParserCapDropsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_parser_cap_drops_total",
			Help: "HTTP/2 events dropped because the per-container parser cap was reached",
		},
		[]string{"destination"},
	)

	// ConnectionsReclaimedTotal counts connectionsByPidFd entries freed by gc().
	//
	// Entries created by createConnectionFromSocketInfo (the Go-TLS fallback) are
	// not registered in activeConnections, so before the gc sweep that reclaims
	// them nothing ever freed them. "dead_pid" is the dominant reason — the
	// process owning the pid+fd is gone; "closed" is a connection that was seen
	// closing and has aged past gcInterval.
	ConnectionsReclaimedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_connections_reclaimed_total",
			Help: "Connection tracking entries reclaimed by gc, by reason",
		},
		[]string{"reason"},
	)

	// ConnectionCapDropsTotal counts connections not tracked because the
	// per-container connectionsByPidFd map was already at
	// maxConnectionsPerContainer.
	//
	// Legitimate entries are bounded by the container's open socket fds, so this
	// should stay zero. Non-zero means gc reclamation is not keeping up and L7
	// events are being dropped for want of a connection record.
	ConnectionCapDropsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "node_agent_connection_cap_drops_total",
			Help: "Connections dropped because the per-container connection cap was reached",
		},
	)

	// Http2ParserStaleReuseTotal counts times a parser was found for a pid/fd
	// but had been created for a different connection (the fd was recycled).
	//
	// Parsers are keyed by pid+fd only. A recycled fd therefore hands the new
	// connection a parser whose HPACK dynamic table belongs to the previous one,
	// which desynchronises decoding immediately. Non-zero here is a direct
	// source of node_agent_hpack_decode_errors_total.
	Http2ParserStaleReuseTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_parser_stale_reuse_total",
			Help: "HTTP/2 parsers reused across different connections on a recycled fd",
		},
		[]string{"destination"},
	)

	// Http2StageTotal counts HTTP/2 requests reaching each stage of the parser
	// pipeline, so the point where they stop can be read directly instead of
	// inferred. Stages, in order:
	//
	//   stream_created   client HEADERS decoded, request object created
	//   response_status  :status seen on the response
	//   end_stream       END_STREAM flag seen (a frame flag, not HPACK)
	//   completed        both of the above -> request emitted
	//   hpack_error      HPACK block failed to decode; decoder reset
	//
	// A request is only emitted with BOTH response_status and end_stream, so
	// whichever stage drops to zero is the blocker.
	Http2StageTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_stage_total",
			Help: "HTTP/2 requests reaching each stage of the parser pipeline",
		},
		[]string{"stage", "destination"},
	)

	// Http2FramesTotal counts HTTP/2 frame headers the parser walks, by type.
	//
	// External HTTP/2 delivers ~44k client-frame events per 5 minutes but only
	// ~71 streams, against ~161k events and ~10.8k streams internally — 86x
	// worse. Either those events contain almost no HEADERS frames, or they are
	// not HTTP/2 at all. Frame type distinguishes the two directly: "invalid"
	// dominating means the bytes are not HTTP/2 and the eBPF port heuristic is
	// over-matching; DATA/WINDOW_UPDATE dominating with no HEADERS means the
	// request headers are being lost before the parser sees them.
	//
	// Deliberately structural. These events carry decrypted application
	// traffic, so dumping payloads to diagnose this would put Authorization
	// headers and request bodies into agent logs; frame type, and the counts
	// alone, disclose nothing.
	Http2FramesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_frames_total",
			Help: "HTTP/2 frame headers parsed, by frame type and destination class",
		},
		[]string{"type", "destination"},
	)

	// Http2PayloadSizeTotal buckets the delivered payload length of HTTP/2
	// events, by destination class and frame direction.
	//
	// 96% of external HTTP/2 events yield no parseable frame (8,881 frames from
	// ~221k events) against 44% internally. Parse() can only produce nothing for
	// three reasons: an empty payload, fewer than 9 bytes (shorter than a frame
	// header), or a first frame header that fails validation — and the third is
	// already counted as type="invalid" in Http2FramesTotal. So the answer is in
	// the size distribution.
	//
	// The "9-16" bucket is the one to watch. A correct HTTP/2 reader does
	// io.ReadFull(header[:9]) and then reads the frame payload separately, so
	// SSL_read returns header-sized and payload-only chunks rather than whole
	// frames. The parser assumes each event begins on a frame boundary and
	// contains complete frames; if external reads are predominantly 9 bytes,
	// that assumption is the bug and the parser needs to treat the connection as
	// a continuous byte stream instead.
	Http2PayloadSizeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "node_agent_http2_payload_size_total",
			Help: "HTTP/2 event payload sizes delivered to the parser, bucketed",
		},
		[]string{"bucket", "destination", "direction"},
	)
)

// TLSAttachTotal counts attempts to attach TLS uprobes to a process, by
// library (go, openssl; "-" when the process could not be registered) and
// outcome (see ebpftracer.TLSAttachResult). A TLS capture gap used to be
// visible only in logs at raised verbosity; a non-zero error,
// attached_no_offsets or not_registered rate is that gap.
var TLSAttachTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "node_agent_tls_attach_total",
		Help: "Attempts to attach TLS uprobes to a process, by library and outcome",
	},
	[]string{"lib", "result"},
)

// L7EventsDroppedTotal counts L7 events discarded in the agent before any
// protocol parsing: the connection or process they belong to was never
// found, or the retry queue for such events was full. Events lost in the
// kernel are counted separately (node_agent_l7_ringbuf_drops_total,
// node_agent_tls_plaintext_dropped_total).
var L7EventsDroppedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "node_agent_l7_events_dropped_total",
		Help: "L7 events dropped in the agent before protocol parsing, by reason, protocol and whether the payload is TLS plaintext",
	},
	[]string{"reason", "protocol", "tls"},
)

type l7DropLogKey struct {
	container ContainerID
	reason    string
	protocol  l7.Protocol
}

// l7DropLogged keeps one log line per container, reason and protocol: the
// counter says how many events are dropped, the line says where.
var l7DropLogged, _ = lru.New[l7DropLogKey, struct{}](4096)

// dropL7Event counts an L7 event dropped before parsing and, the first time
// for its container, reason and protocol, logs the process and destination.
// container is empty when the event's process belongs to no known container.
func dropL7Event(container ContainerID, reason string, pid uint32, fd uint64, req *l7.RequestData, si *ebpftracer.SocketInfo) {
	L7EventsDroppedTotal.WithLabelValues(reason, protocolLabel(req.Protocol), strconv.FormatBool(req.TLS)).Inc()
	if ok, _ := l7DropLogged.ContainsOrAdd(l7DropLogKey{container: container, reason: reason, protocol: req.Protocol}, struct{}{}); ok {
		return
	}
	dst := "unknown"
	if si != nil && si.Valid {
		dst = net.JoinHostPort(si.DstIP, strconv.Itoa(int(si.DstPort)))
	}
	klog.Infof("L7 events dropped before parsing: reason=%s protocol=%s tls=%t container=%s pid=%d fd=%d dst=%s (logged once per container, reason and protocol)",
		reason, protocolLabel(req.Protocol), req.TLS, container, pid, fd, dst)
}

// RegisterL7SelfMetrics registers the agent's L7 self-observability counters
// and wires the l7-package callbacks that increment them.
func RegisterL7SelfMetrics(reg prometheus.Registerer) {
	reg.MustRegister(
		HPACKDecodeErrorsTotal,
		L7EventsTotal,
		L7PayloadTruncatedTotal,
		Http2ParserCapDropsTotal,
		ConnectionsReclaimedTotal,
		ConnectionCapDropsTotal,
		Http2ParserStaleReuseTotal,
		Http2StageTotal,
		Http2FramesTotal,
		Http2PayloadSizeTotal,
		TLSAttachTotal,
		L7EventsDroppedTotal,
	)
	// Hook the HTTP/2 parser's HPACK error path so we get a counter without
	// l7 having to import prometheus.
	l7.OnHPACKDecodeError = func() { HPACKDecodeErrorsTotal.Inc() }
	// Pre-resolve the frame counters. OnHttp2Frame fires per frame — measured
	// around 1.6k/s — and WithLabelValues hashes the labels and takes the
	// vector's read lock on every call. The label sets are small and fixed, so
	// resolving them once at startup keeps that off the parser's hot path.
	frameTypes := []string{
		"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE",
		"PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION", "extension", "invalid",
	}
	dests := []string{"external", "internal", "unknown"}
	frameCounters := make(map[string]map[string]prometheus.Counter, len(frameTypes))
	for _, ft := range frameTypes {
		byDest := make(map[string]prometheus.Counter, len(dests))
		for _, d := range dests {
			byDest[d] = Http2FramesTotal.WithLabelValues(ft, d)
		}
		frameCounters[ft] = byDest
	}
	l7.OnHttp2Frame = func(frameType, dest string) {
		if dest == "" {
			dest = "unknown"
		}
		if byDest := frameCounters[frameType]; byDest != nil {
			if c := byDest[dest]; c != nil {
				c.Inc()
				return
			}
		}
		// Unrecognised combination: fall back rather than drop the observation.
		Http2FramesTotal.WithLabelValues(frameType, dest).Inc()
	}
	l7.OnHttp2Stage = func(stage, dest string) {
		if dest == "" {
			dest = "unknown"
		}
		Http2StageTotal.WithLabelValues(stage, dest).Inc()
	}
}
