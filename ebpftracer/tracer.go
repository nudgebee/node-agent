package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	MaxPayloadSize = 4096 // Must match MAX_PAYLOAD_SIZE in eBPF

	l7EventHeaderSize = 96 // 56 bytes base + 40 bytes socket tuple fields
	tcpEventSize      = 104
	fileEventSize     = 32
	procEventSize     = 12
)

type EventType uint32
type EventReason uint32

const (
	EventTypeProcessStart     EventType = 1
	EventTypeProcessExit      EventType = 2
	EventTypeConnectionOpen   EventType = 3
	EventTypeConnectionClose  EventType = 4
	EventTypeConnectionError  EventType = 5
	EventTypeListenOpen       EventType = 6
	EventTypeListenClose      EventType = 7
	EventTypeFileOpen         EventType = 8
	EventTypeTCPRetransmit    EventType = 9
	EventTypeL7Request        EventType = 10
	EventTypePythonThreadLock EventType = 11
	EventTypeLLMData          EventType = 12
	EventTypeProcessExec      EventType = 13

	EventReasonNone    EventReason = 0
	EventReasonOOMKill EventReason = 1
)

type TrafficStats struct {
	BytesSent     uint64
	BytesReceived uint64
}

type Event struct {
	Type          EventType
	Reason        EventReason
	Pid           uint32
	SrcAddr       netaddr.IPPort
	DstAddr       netaddr.IPPort
	ActualDstAddr netaddr.IPPort
	Fd            uint64
	Timestamp     uint64
	Duration      time.Duration
	L7Request     *l7.RequestData
	TrafficStats  *TrafficStats
	Mnt           uint64
	Log           bool
	// Socket info extracted directly from fd in eBPF (for L7 events)
	// This enables processing L7 events even when TCP connection tracking failed
	SocketInfo *SocketInfo
	// LLMData is one chunk of a connection marked for LLM capture.
	LLMData *LLMData
}

// LLMData is a chunk of the byte stream of a connection marked with
// TagLLMConnection. Event.Timestamp is the connection's timestamp.
type LLMData struct {
	Ingress bool   // read by the application, rather than written
	Time    uint64 // kernel time of the read or write, in ns
	Data    []byte
	// SkipAfter is the number of bytes of the same read or write that were
	// not captured, and follow Data.
	SkipAfter uint64
}

type perfMapType uint8

const (
	perfMapTypeProcEvents         perfMapType = 1
	perfMapTypeTCPEvents          perfMapType = 2
	perfMapTypeFileEvents         perfMapType = 3
	perfMapTypeL7Events           perfMapType = 4
	perfMapTypePythonThreadEvents perfMapType = 5
)

type Tracer struct {
	disableL7Tracing bool
	enableLLMCapture bool
	hostNetNs        netns.NsHandle
	selfNetNs        netns.NsHandle

	collection    *ebpf.Collection
	readers       map[string]*perf.Reader
	ringbufReader *ringbuf.Reader // Ring buffer reader for l7_events
	links         []link.Link
	uprobes       map[string]*ebpf.Program

	// programVariant is the compiled variant loaded for this kernel (see
	// collectionSpecForKernel). kernelBTF and socketOffsets record whether
	// the kernel's BTF loaded and whether the socket struct offsets taken
	// from it were set (see initSocketInfoOffsets). programInstructions
	// holds each loaded program's size after the kernel rewrote it.
	programVariant      string
	kernelBTF           bool
	socketOffsets       bool
	programInstructions []ProgramInstructions

	// ready is set once Run has loaded the eBPF collection and completed the
	// initial process scan. Consumers running before Run completes (e.g. the
	// registry event-handler goroutine) must check it before touching
	// collection maps.
	ready atomic.Bool
}

func NewTracer(hostNetNs, selfNetNs netns.NsHandle, disableL7Tracing, enableLLMCapture bool) *Tracer {
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
	}
	// LLM capture rides on the L7 programs.
	enableLLMCapture = enableLLMCapture && !disableL7Tracing
	if enableLLMCapture {
		klog.Infoln("LLM capture is enabled")
	}
	return &Tracer{
		disableL7Tracing: disableL7Tracing,
		enableLLMCapture: enableLLMCapture,
		hostNetNs:        hostNetNs,
		selfNetNs:        selfNetNs,

		readers: map[string]*perf.Reader{},
		uprobes: map[string]*ebpf.Program{},
	}
}

func (t *Tracer) Run(events chan<- Event) error {
	if err := proc.ExecuteInNetNs(t.hostNetNs, t.selfNetNs, ensureConntrackEventsAreEnabled); err != nil {
		return err
	}
	if err := t.ebpf(events); err != nil {
		return err
	}
	if err := t.init(events); err != nil {
		return err
	}
	t.ready.Store(true)
	return nil
}

// Ready reports whether Run has loaded the eBPF collection and finished the
// initial process scan. Map iterators must not be used until this returns true.
func (t *Tracer) Ready() bool {
	return t.ready.Load()
}

func (t *Tracer) Close() {
	for _, p := range t.uprobes {
		_ = p.Close()
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	for _, r := range t.readers {
		_ = r.Close()
	}
	// Close ring buffer reader for l7_events
	if t.ringbufReader != nil {
		_ = t.ringbufReader.Close()
	}
	t.collection.Close()
}

// TLSCiphertextSkipped returns how many socket-level writes and reads the
// kernel dropped because a TLS hook already delivers that connection's
// plaintext. ok is false until the eBPF collection is loaded.
func (t *Tracer) TLSCiphertextSkipped() (writes, reads uint64, ok bool) {
	m := t.readyMap("tls_ciphertext_skipped")
	if m == nil {
		return 0, 0, false
	}
	return sumPerCPU(m, 0), sumPerCPU(m, 1), true
}

// ActualDestination returns the post-NAT destination of the TCP connection
// whose local address is src, as the kernel recorded it from conntrack
// (actual_destinations in conntrack.c). It is what a connection's open event
// carries as its actual destination; ok is false if no translation was seen.
func (t *Tracer) ActualDestination(src netaddr.IPPort) (netaddr.IPPort, bool) {
	m := t.readyMap("actual_destinations")
	if m == nil {
		return netaddr.IPPort{}, false
	}
	// struct ipPort: a 16-byte address (IPv4-mapped for IPv4) and a port in
	// host byte order.
	var key, value [18]byte
	ip := src.IP().As16()
	copy(key[:16], ip[:])
	binary.LittleEndian.PutUint16(key[16:], src.Port())
	if err := m.Lookup(key, &value); err != nil {
		return netaddr.IPPort{}, false
	}
	return ipPort(value[:16], binary.LittleEndian.Uint16(value[16:])), true
}

// tlsDropReasons names the indexes of the tls_plaintext_dropped map
// (TLS_DROP_* in l7.c).
var tlsDropReasons = []string{"go_fd_unknown", "ssl_read_fd_unknown", "ssl_write_unclaimed"}

// TLSPlaintextDropped returns, per reason, how much TLS plaintext the kernel
// saw in a library hook but could not attribute to a socket. ok is false
// until the eBPF collection is loaded.
func (t *Tracer) TLSPlaintextDropped() (map[string]uint64, bool) {
	m := t.readyMap("tls_plaintext_dropped")
	if m == nil {
		return nil, false
	}
	res := make(map[string]uint64, len(tlsDropReasons))
	for i, reason := range tlsDropReasons {
		res[reason] = sumPerCPU(m, uint32(i))
	}
	return res, true
}

// goTLSFdResolvedMethods names the methods of the go_tls_fd_resolved map
// (GO_FD_RESOLVED_* in gotls.c), and goConnMaxDepth is GO_CONN_MAX_DEPTH.
var goTLSFdResolvedMethods = []string{"itab", "socket", "shape"}

const goConnMaxDepth = 4

// GoTLSFdResolved is how many Go crypto/tls calls had their socket fd found
// by one method at one wrapper depth.
type GoTLSFdResolved struct {
	Method string
	Depth  int
	Count  uint64
}

// GoTLSFdResolved returns, per method and depth, how many Go crypto/tls calls
// had their socket fd found: by the binary's *net.TCPConn itab ("itab"), by
// the shape of the connection confirmed against the kernel's socket
// ("socket"), or by the shape alone, on a kernel without BTF ("shape"). ok is
// false until the eBPF collection is loaded.
func (t *Tracer) GoTLSFdResolved() ([]GoTLSFdResolved, bool) {
	m := t.readyMap("go_tls_fd_resolved")
	if m == nil {
		return nil, false
	}
	res := make([]GoTLSFdResolved, 0, len(goTLSFdResolvedMethods)*goConnMaxDepth)
	for i, method := range goTLSFdResolvedMethods {
		for depth := 0; depth < goConnMaxDepth; depth++ {
			n := sumPerCPU(m, uint32(i*goConnMaxDepth+depth))
			res = append(res, GoTLSFdResolved{Method: method, Depth: depth, Count: n})
		}
	}
	return res, true
}

// EBPFInfo describes what the kernel gave the eBPF programs to work with.
type EBPFInfo struct {
	// ProgramVariant is the compiled variant loaded for this kernel: its
	// minimum kernel version, with "-cep" for the ctx-extra-padding build.
	ProgramVariant string
	// KernelBTF is whether the kernel's BTF loaded.
	KernelBTF bool
	// SocketOffsets is whether the socket struct offsets read from it were
	// set. Without them the kernel cannot read a socket's addresses from its
	// fd, and the Go TLS fd walk cannot confirm what it found.
	SocketOffsets bool
	// Programs is each loaded program's size after the kernel rewrote it.
	Programs []ProgramInstructions
}

// ProgramInstructions is a loaded program's size. Xlated is the instruction
// count after the kernel rewrote the program; Verified, where the kernel
// reports it (5.16+), is how many instructions the verifier processed, which
// is what its complexity limit applies to.
type ProgramInstructions struct {
	Program  string
	Xlated   int
	Verified uint32
}

// EBPFInfo returns what the kernel gave the eBPF programs; ok is false until
// the eBPF collection is loaded.
func (t *Tracer) EBPFInfo() (EBPFInfo, bool) {
	if !t.ready.Load() || t.collection == nil {
		return EBPFInfo{}, false
	}
	return EBPFInfo{
		ProgramVariant: t.programVariant,
		KernelBTF:      t.kernelBTF,
		SocketOffsets:  t.socketOffsets,
		Programs:       t.programInstructions,
	}, true
}

// tlsDropKey is struct tls_drop_key in l7.c.
type tlsDropKey struct{ Pid, Reason uint32 }

// TLSPlaintextDroppedByPid returns, per process and reason, the TLS plaintext
// losses the kernel attributed since the last call (tls_plaintext_dropped_by_pid),
// and clears them.
func (t *Tracer) TLSPlaintextDroppedByPid() map[uint32]map[string]uint64 {
	m := t.readyMap("tls_plaintext_dropped_by_pid")
	if m == nil {
		return nil
	}
	var keys []tlsDropKey
	var k tlsDropKey
	var v uint64
	for it := m.Iterate(); it.Next(&k, &v); {
		keys = append(keys, k)
	}
	res := map[uint32]map[string]uint64{}
	for _, k := range keys {
		var n uint64
		err := m.LookupAndDelete(k, &n)
		if errors.Is(err, ebpf.ErrNotSupported) {
			// Hash-map LookupAndDelete needs 5.14; a count that lands between
			// these two calls is lost, which is fine for a diagnostic.
			if m.Lookup(k, &n) != nil {
				continue
			}
			_ = m.Delete(k)
		} else if err != nil {
			continue
		}
		if n == 0 || int(k.Reason) >= len(tlsDropReasons) {
			continue
		}
		if res[k.Pid] == nil {
			res[k.Pid] = map[string]uint64{}
		}
		res[k.Pid][tlsDropReasons[k.Reason]] += n
	}
	return res
}

// TLSPlaintextDroppedForPid returns and clears the losses attributed to one
// process. It is called when the process exits, which is the last chance to
// attribute them: a short-lived process is gone before the periodic read.
func (t *Tracer) TLSPlaintextDroppedForPid(pid uint32) map[string]uint64 {
	m := t.readyMap("tls_plaintext_dropped_by_pid")
	if m == nil {
		return nil
	}
	var res map[string]uint64
	for reason, name := range tlsDropReasons {
		k := tlsDropKey{Pid: pid, Reason: uint32(reason)}
		var n uint64
		if m.Lookup(k, &n) != nil {
			continue
		}
		_ = m.Delete(k)
		if n > 0 {
			if res == nil {
				res = map[string]uint64{}
			}
			res[name] = n
		}
	}
	return res
}

// L7RingbufDrops returns how many L7 events the kernel lost because the
// l7_events ring buffer was full.
func (t *Tracer) L7RingbufDrops() (uint64, bool) {
	m := t.readyMap("l7_ringbuf_drops")
	if m == nil {
		return 0, false
	}
	return sumPerCPU(m, 0), true
}

// LLMCaptureDrops returns how many LLM capture chunks the kernel lost because
// the llm_events ring buffer was full.
func (t *Tracer) LLMCaptureDrops() (uint64, bool) {
	if !t.enableLLMCapture {
		return 0, false
	}
	m := t.readyMap("llm_capture_drops")
	if m == nil {
		return 0, false
	}
	return sumPerCPU(m, 0), true
}

// TagLLMConnection marks a connection for LLM capture: from now on the kernel
// copies all of its reads and writes to the llm_events ring buffer instead of
// the generic L7 path. connTimestamp is the connection's timestamp from its L7
// events, which keeps the mark from applying to a later connection reusing the
// fd. The kernel removes the mark when the fd is closed.
func (t *Tracer) TagLLMConnection(pid uint32, fd uint64, connTimestamp uint64) error {
	if !t.enableLLMCapture {
		return errors.New("LLM capture is disabled")
	}
	m := t.readyMap("llm_conns")
	if m == nil {
		return errors.New("ebpf collection not loaded")
	}
	return m.Update(ConnectionId{FD: fd, PID: pid}, connTimestamp, ebpf.UpdateAny)
}

// TagLLMDestination marks a destination, as a socket sees it (before any
// NAT), as an LLM API endpoint: every new connection to it is captured from
// its first write.
func (t *Tracer) TagLLMDestination(ip netaddr.IP, port uint16) error {
	if !t.enableLLMCapture {
		return errors.New("LLM capture is disabled")
	}
	m := t.readyMap("llm_dests")
	if m == nil {
		return errors.New("ebpf collection not loaded")
	}
	var key [24]byte
	if ip.Is4() {
		a := ip.As4()
		copy(key[0:4], a[:])
	} else {
		a := ip.As16()
		copy(key[0:16], a[:])
	}
	binary.LittleEndian.PutUint16(key[16:18], port)
	return m.Update(key, uint8(1), ebpf.UpdateAny)
}

func (t *Tracer) readyMap(name string) *ebpf.Map {
	if !t.ready.Load() || t.collection == nil {
		return nil
	}
	return t.collection.Maps[name]
}

func sumPerCPU(m *ebpf.Map, key uint32) uint64 {
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

func (t *Tracer) ActiveConnectionsIterator() *ebpf.MapIterator {
	return t.collection.Maps["active_connections"].Iterate()
}

func (t *Tracer) NodejsStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["nodejs_stats"].Iterate()
}

func (t *Tracer) PythonStatsIterator() *ebpf.MapIterator {
	return t.collection.Maps["python_stats"].Iterate()
}

type NodejsStats struct {
	EventLoopBlockedTime time.Duration
}

type PythonStats struct {
	ThreadLockWaitTime time.Duration
}

type ConnectionId struct {
	FD  uint64
	PID uint32
	_   uint32
}

type Connection struct {
	BytesSent     uint64
	BytesReceived uint64
	Timestamp     uint64
	Protocol      uint8
	_             [7]byte // Explicit padding
}

type perfMap struct {
	name                  string
	perCPUBufferSizePages int
	typ                   perfMapType
	readTimeout           time.Duration
}

// collectionSpecForKernel returns the compiled program variant for the running
// kernel, ready to load, and the variant's name: the minimum kernel version it
// was built for, with "-cep" for the ctx-extra-padding build.
func collectionSpecForKernel() (*ebpf.CollectionSpec, string, error) {
	if _, ok := ebpfProgs[runtime.GOARCH]; !ok {
		return nil, "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	var traceFsPath string
	for _, p := range []string{"/sys/kernel/debug/tracing", "/sys/kernel/tracing"} {
		if _, err := os.Stat(p); err == nil {
			traceFsPath = p
			break
		}
	}
	if traceFsPath == "" {
		return nil, "", fmt.Errorf("kernel tracing is not available: debugfs or tracefs must be mounted")
	}

	var flags string
	if isCtxExtraPaddingRequired(traceFsPath) {
		flags = "ctx-extra-padding"
	}
	kv := common.GetKernelVersion()
	var prog []byte
	var variant string
	for _, p := range ebpfProgs[runtime.GOARCH] {
		pv, _ := common.VersionFromString(p.version)
		if !kv.GreaterOrEqual(pv) {
			continue
		}
		if flags != p.flags {
			continue
		}
		prog = p.prog
		variant = p.version
		if p.flags != "" {
			variant += "-cep"
		}
		break
	}
	if len(prog) == 0 {
		return nil, "", fmt.Errorf("unsupported kernel version: %s %s", kv, flags)
	}

	reader, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(prog)))
	if err != nil {
		return nil, "", fmt.Errorf("invalid program encoding: %w", err)
	}
	prog, err = io.ReadAll(reader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to ungzip program: %w", err)
	}
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return nil, "", fmt.Errorf("failed to load collection spec: %w", err)
	}
	if heap, ok := collectionSpec.Maps["llm_event_heap"]; ok {
		cpus, err := ebpf.PossibleCPU()
		if err != nil {
			return nil, "", fmt.Errorf("failed to count possible CPUs: %w", err)
		}
		heap.MaxEntries = uint32(cpus)
	}
	return collectionSpec, variant, nil
}

func (t *Tracer) ebpf(ch chan<- Event) error {
	collectionSpec, variant, err := collectionSpecForKernel()
	if err != nil {
		return err
	}
	t.programVariant = variant
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	c, err := ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{
		//Programs: ebpf.ProgramOptions{LogLevel: 2, LogSize: 20 * 1024 * 1024},
	})
	if err != nil {
		var vErr *ebpf.VerifierError
		if errors.As(err, &vErr) {
			klog.Errorf("%+v", vErr)
		}
		return fmt.Errorf("failed to load collection: %w", err)
	}
	t.collection = c
	t.programInstructions = programInstructions(c)

	if t.enableLLMCapture {
		if err := c.Maps["llm_capture_config"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to enable LLM capture: %w", err)
		}
	}

	// Initialize socket info offsets for direct fd->socket tuple extraction
	// This enables L7 event processing without dependency on TCP connection tracking
	if err := t.initSocketInfoOffsets(); err != nil {
		klog.Warningf("Failed to initialize socket info offsets: %v", err)
		// Not fatal - socket info extraction just won't work
	}

	perfMaps := []perfMap{
		// Read as often as connect events: an exec is acted on (TLS probes
		// attached) before the new program makes its first connection.
		{name: "proc_events", typ: perfMapTypeProcEvents, perCPUBufferSizePages: 4, readTimeout: 10 * time.Millisecond},
		{name: "tcp_listen_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "tcp_connect_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 8, readTimeout: 10 * time.Millisecond},
		{name: "tcp_retransmit_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "file_events", typ: perfMapTypeFileEvents, perCPUBufferSizePages: 4},
	}

	// Create perf buffer readers for non-L7 events
	pageSize := os.Getpagesize()
	for _, pm := range perfMaps {
		r, err := perf.NewReaderWithOptions(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*pageSize, perf.ReaderOptions{WakeupEvents: 100})
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go runEventsReader(pm.name, r, ch, pm.typ, pm.readTimeout)
	}

	// Create ring buffer reader for l7_events (provides global ordering for SSE streaming)
	if !t.disableL7Tracing {
		ringbufReader, err := ringbuf.NewReader(t.collection.Maps["l7_events"])
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ring buffer reader for l7_events: %w", err)
		}
		t.ringbufReader = ringbufReader
		go runRingbufEventsReader("l7_events", ringbufReader, ch)
	}

	for _, programSpec := range collectionSpec.Programs {
		program := t.collection.Programs[programSpec.Name]
		if t.disableL7Tracing {
			switch programSpec.Name {
			case "sys_enter_writev", "sys_enter_write", "sys_enter_sendto", "sys_enter_sendmsg", "sys_enter_sendmmsg":
				continue
			case "sys_enter_read", "sys_enter_readv", "sys_enter_recvfrom", "sys_enter_recvmsg":
				continue
			case "sys_exit_read", "sys_exit_readv", "sys_exit_recvfrom", "sys_exit_recvmsg":
				continue
			}
		}
		var l link.Link
		switch programSpec.Type {
		case ebpf.TracePoint:
			parts := strings.SplitN(programSpec.AttachTo, "/", 2)
			l, err = link.Tracepoint(parts[0], parts[1], program, nil)
		case ebpf.Kprobe:
			if strings.HasPrefix(programSpec.SectionName, "uprobe/") || strings.HasPrefix(programSpec.SectionName, "uretprobe/") {
				t.uprobes[programSpec.Name] = program
				continue
			}
			l, err = link.Kprobe(programSpec.AttachTo, program, nil)
			if err != nil && programSpec.SectionName == "kprobe/nf_ct_deliver_cached_events" {
				klog.Warningln("nf_conntrack may not be in use:", err)
				continue
			}
		}
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to link program '%s': %w", programSpec.Name, err)
		}
		t.links = append(t.links, l)
	}

	// SSL uprobes are handled per-process in tls.go via AttachOpenSslUprobes()

	return nil
}

// programInstructions reads each program's size from the kernel. It is read
// once, at load: the sizes cannot change afterwards.
func programInstructions(c *ebpf.Collection) []ProgramInstructions {
	res := make([]ProgramInstructions, 0, len(c.Programs))
	for name, p := range c.Programs {
		info, err := p.Info()
		if err != nil {
			continue
		}
		pi := ProgramInstructions{Program: name}
		if size, err := info.TranslatedSize(); err == nil {
			pi.Xlated = size / 8
		}
		pi.Verified, _ = info.VerifiedInstructions()
		res = append(res, pi)
	}
	return res
}

func (t EventType) String() string {
	switch t {
	case EventTypeProcessStart:
		return "process-start"
	case EventTypeProcessExit:
		return "process-exit"
	case EventTypeProcessExec:
		return "process-exec"
	case EventTypeConnectionOpen:
		return "connection-open"
	case EventTypeConnectionClose:
		return "connection-close"
	case EventTypeConnectionError:
		return "connection-error"
	case EventTypeListenOpen:
		return "listen-open"
	case EventTypeListenClose:
		return "listen-close"
	case EventTypeFileOpen:
		return "file-open"
	case EventTypeTCPRetransmit:
		return "tcp-retransmit"
	case EventTypeL7Request:
		return "l7-request"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

func (t EventReason) String() string {
	switch t {
	case EventReasonNone:
		return "none"
	case EventReasonOOMKill:
		return "oom-kill"
	}
	return "unknown: " + strconv.Itoa(int(t))
}

type procEvent struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

type tcpEvent struct {
	Fd            uint64
	Timestamp     uint64
	Duration      uint64
	Type          EventType
	Pid           uint32
	BytesSent     uint64
	BytesReceived uint64
	SPort         uint16
	DPort         uint16
	Aport         uint16
	SAddr         [16]byte
	DAddr         [16]byte
	AAddr         [16]byte
}

type fileEvent struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type l7Event struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	Status              int32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	StatementId         uint32
	PayloadSize         uint64
	ResponseSize        uint64
	// Socket tuple - extracted directly from fd in eBPF, no TCP event dependency
	Saddr           [16]byte // Source address (IPv4 in first 4 bytes, or full IPv6)
	Daddr           [16]byte // Destination address
	Sport           uint16   // Source port
	Dport           uint16   // Destination port
	AddrFamily      uint16   // AF_INET (2) or AF_INET6 (10)
	SocketInfoValid uint8    // 1 if socket info was extracted
	Padding2        uint8
	Payload         [MaxPayloadSize]byte // Must match MAX_PAYLOAD_SIZE in eBPF
	Response        [MaxPayloadSize]byte // Must match MAX_PAYLOAD_SIZE in eBPF
}

// lostSamplesTracker tracks lost samples per perf map and logs them periodically
type lostSamplesTracker struct {
	count    atomic.Uint64
	lastLog  atomic.Int64 // Unix timestamp in seconds
	interval int64        // Log interval in seconds
}

var lostSamplesTrackers = sync.Map{} // map[string]*lostSamplesTracker

func getLostSamplesTracker(name string) *lostSamplesTracker {
	tracker, ok := lostSamplesTrackers.Load(name)
	if !ok {
		tracker, _ = lostSamplesTrackers.LoadOrStore(name, &lostSamplesTracker{interval: 10})
	}
	t, ok := tracker.(*lostSamplesTracker)
	if !ok {
		// Only this function ever writes the map, so this is unreachable; return a
		// throwaway rather than panicking in a metrics path.
		return &lostSamplesTracker{interval: 10}
	}
	return t
}

// safeDuration converts a uint64 nanosecond value from eBPF to time.Duration.
// Returns 0 for values that would overflow int64 (>= 2^63) or exceed 1 hour,
// which indicate corrupted eBPF timestamps.
func safeDuration(ns uint64) time.Duration {
	if ns == 0 || ns >= uint64(time.Hour) {
		return 0
	}
	return time.Duration(ns)
}

// clampSize safely converts a uint64 size to int, capping at maxSize.
// Prevents negative int from uint64 values with the high bit set.
func clampSize(size uint64, maxSize int) int {
	if size > uint64(maxSize) {
		return maxSize
	}
	return int(size)
}

func (t *lostSamplesTracker) recordLostSamples(name string, count uint64, cpu int) {
	t.count.Add(count)
	now := time.Now().Unix()
	lastLog := t.lastLog.Load()
	if now-lastLog >= t.interval {
		if t.lastLog.CompareAndSwap(lastLog, now) {
			total := t.count.Swap(0)
			if total > 0 {
				// Use standard log package to avoid klog's multi-severity output
				log.Printf("ERROR: %s lost %d samples total (last on CPU %d) in the last %d seconds", name, total, cpu, t.interval)
			}
		}
	}
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, typ perfMapType, readTimeout time.Duration) {
	tracker := getLostSamplesTracker(name)
	if readTimeout == 0 {
		readTimeout = 100 * time.Millisecond
	}
	for {
		r.SetDeadline(time.Now().Add(readTimeout))
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			continue
		}
		if rec.LostSamples > 0 {
			tracker.recordLostSamples(name, rec.LostSamples, rec.CPU)
			continue
		}
		var event Event

		switch typ {
		case perfMapTypeL7Events:
			data := rec.RawSample
			if len(data) < l7EventHeaderSize {
				klog.Warningln("invalid l7 event size:", len(data))
				continue
			}
			payloadSize := binary.LittleEndian.Uint64(data[40:48])
			responseSize := binary.LittleEndian.Uint64(data[48:56])
			payloadLen := clampSize(payloadSize, MaxPayloadSize)
			responseLen := clampSize(responseSize, MaxPayloadSize)

			payloadData := make([]byte, payloadLen)
			if l7EventHeaderSize+payloadLen <= len(data) {
				copy(payloadData, data[l7EventHeaderSize:l7EventHeaderSize+payloadLen])
			}

			responseData := make([]byte, responseLen)
			respOffset := l7EventHeaderSize + MaxPayloadSize
			if respOffset+responseLen <= len(data) {
				copy(responseData, data[respOffset:respOffset+responseLen])
			}

			req := &l7.RequestData{
				Protocol:     l7.Protocol(data[32]),
				Method:       l7.Method(data[33]),
				TLS:          data[34] != 0,
				KernelTime:   binary.LittleEndian.Uint64(data[24:32]),
				Status:       l7.Status(int32(binary.LittleEndian.Uint32(data[20:24]))),
				Duration:     safeDuration(binary.LittleEndian.Uint64(data[24:32])),
				StatementId:  binary.LittleEndian.Uint32(data[36:40]),
				PayloadSize:  payloadSize,
				ResponseSize: responseSize,
				Payload:      payloadData,
				Response:     responseData,
			}

			event = Event{
				Type:      EventTypeL7Request,
				Pid:       binary.LittleEndian.Uint32(data[16:20]),
				Fd:        binary.LittleEndian.Uint64(data[0:8]),
				Timestamp: binary.LittleEndian.Uint64(data[8:16]),
				L7Request: req,
			}
		case perfMapTypeFileEvents:
			if len(rec.RawSample) < fileEventSize {
				klog.Warningln("invalid file event size:", len(rec.RawSample))
				continue
			}
			event = Event{
				Type: EventType(binary.LittleEndian.Uint32(rec.RawSample[0:4])),
				Pid:  binary.LittleEndian.Uint32(rec.RawSample[4:8]),
				Fd:   binary.LittleEndian.Uint64(rec.RawSample[8:16]),
				Mnt:  binary.LittleEndian.Uint64(rec.RawSample[16:24]),
				Log:  binary.LittleEndian.Uint64(rec.RawSample[24:32]) > 0,
			}
		case perfMapTypeProcEvents:
			if len(rec.RawSample) < procEventSize {
				klog.Warningln("invalid proc event size:", len(rec.RawSample))
				continue
			}
			event = Event{
				Type:   EventType(binary.LittleEndian.Uint32(rec.RawSample[0:4])),
				Pid:    binary.LittleEndian.Uint32(rec.RawSample[4:8]),
				Reason: EventReason(binary.LittleEndian.Uint32(rec.RawSample[8:12])),
			}
		case perfMapTypeTCPEvents:
			if len(rec.RawSample) < tcpEventSize {
				klog.Warningln("invalid tcp event size:", len(rec.RawSample))
				continue
			}
			data := rec.RawSample
			typ := EventType(binary.LittleEndian.Uint32(data[24:28]))
			event = Event{
				Type:          typ,
				Pid:           binary.LittleEndian.Uint32(data[28:32]),
				SrcAddr:       ipPort(data[54:70], binary.LittleEndian.Uint16(data[48:50])),
				DstAddr:       ipPort(data[70:86], binary.LittleEndian.Uint16(data[50:52])),
				ActualDstAddr: ipPort(data[86:102], binary.LittleEndian.Uint16(data[52:54])),
				Fd:            binary.LittleEndian.Uint64(data[0:8]),
				Timestamp:     binary.LittleEndian.Uint64(data[8:16]),
				Duration:      safeDuration(binary.LittleEndian.Uint64(data[16:24])),
			}
			if typ == EventTypeConnectionClose {
				event.TrafficStats = &TrafficStats{
					BytesSent:     binary.LittleEndian.Uint64(data[32:40]),
					BytesReceived: binary.LittleEndian.Uint64(data[40:48]),
				}
			}
		default:
			continue
		}

		ch <- event
	}
}

// runRingbufEventsReader reads L7 events from ring buffer
// Ring buffer provides global event ordering across CPUs, which is important
// for streaming responses (SSE) where chunk order matters
func runRingbufEventsReader(name string, r *ringbuf.Reader, ch chan<- Event) {
	// One record reused for every read: everything sent on ch is copied out of
	// RawSample first, and a fresh buffer per event was 10-20% of the agent's
	// allocated bytes.
	var rec ringbuf.Record
	for {
		err := r.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				klog.V(2).Infof("ring buffer reader %s closed", name)
				break
			}
			klog.Warningf("failed to read from ring buffer %s: %v", name, err)
			continue
		}

		data := rec.RawSample
		if len(data) > l7EventProtocolByte && data[l7EventProtocolByte] == protocolLLMCapture {
			if ev, ok := decodeLLMEvent(data); ok {
				ch <- ev
			}
			continue
		}
		if len(data) < l7EventHeaderSize {
			klog.Warningln("invalid l7 event from ring buffer, size:", len(data))
			continue
		}

		payloadSize := binary.LittleEndian.Uint64(data[40:48])
		responseSize := binary.LittleEndian.Uint64(data[48:56])
		payloadLen := clampSize(payloadSize, MaxPayloadSize)
		responseLen := clampSize(responseSize, MaxPayloadSize)

		payloadData := make([]byte, payloadLen)
		if l7EventHeaderSize+payloadLen <= len(data) {
			copy(payloadData, data[l7EventHeaderSize:l7EventHeaderSize+payloadLen])
		}

		responseData := make([]byte, responseLen)
		respOffset := l7EventHeaderSize + MaxPayloadSize
		if respOffset+responseLen <= len(data) {
			copy(responseData, data[respOffset:respOffset+responseLen])
		}

		req := &l7.RequestData{
			Protocol:     l7.Protocol(data[32]),
			Method:       l7.Method(data[33]),
			TLS:          data[34] != 0,
			KernelTime:   binary.LittleEndian.Uint64(data[24:32]),
			Status:       l7.Status(int32(binary.LittleEndian.Uint32(data[20:24]))),
			Duration:     safeDuration(binary.LittleEndian.Uint64(data[24:32])),
			StatementId:  binary.LittleEndian.Uint32(data[36:40]),
			PayloadSize:  payloadSize,
			ResponseSize: responseSize,
			Payload:      payloadData,
			Response:     responseData,
		}

		// Extract socket info from raw bytes
		var socketInfo *SocketInfo
		if data[94] != 0 { // SocketInfoValid at offset 94
			var saddr, daddr [16]byte
			copy(saddr[:], data[56:72])
			copy(daddr[:], data[72:88])
			addrFamily := binary.LittleEndian.Uint16(data[92:94])
			socketInfo = &SocketInfo{
				SrcIP:   extractIPFromSocketInfo(saddr, addrFamily),
				DstIP:   extractIPFromSocketInfo(daddr, addrFamily),
				SrcPort: binary.LittleEndian.Uint16(data[88:90]),
				DstPort: binary.LittleEndian.Uint16(data[90:92]),
				Family:  addrFamily,
				Valid:   true,
			}
		}

		event := Event{
			Type:       EventTypeL7Request,
			Pid:        binary.LittleEndian.Uint32(data[16:20]),
			Fd:         binary.LittleEndian.Uint64(data[0:8]),
			Timestamp:  binary.LittleEndian.Uint64(data[8:16]),
			L7Request:  req,
			SocketInfo: socketInfo,
		}

		ch <- event
	}
}

// llmEventHeaderSize is the size of struct llm_event before its data, and
// protocolLLMCapture marks one in l7_events (PROTOCOL_LLM_CAPTURE).
const (
	llmEventHeaderSize  = 48
	protocolLLMCapture  = 0xFE
	l7EventProtocolByte = 32
)

func decodeLLMEvent(d []byte) (Event, bool) {
	if len(d) < llmEventHeaderSize {
		return Event{}, false
	}
	n := int(binary.LittleEndian.Uint32(d[20:24]))
	if llmEventHeaderSize+n > len(d) {
		return Event{}, false
	}
	return Event{
		Type:      EventTypeLLMData,
		Fd:        binary.LittleEndian.Uint64(d[0:8]),
		Timestamp: binary.LittleEndian.Uint64(d[8:16]),
		Pid:       binary.LittleEndian.Uint32(d[16:20]),
		LLMData: &LLMData{
			Time:      binary.LittleEndian.Uint64(d[24:32]),
			Ingress:   d[33] == 1,
			SkipAfter: binary.LittleEndian.Uint64(d[40:48]),
			Data:      append([]byte(nil), d[llmEventHeaderSize:llmEventHeaderSize+n]...),
		},
	}, true
}

func ipPort(ip []byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip)
	return netaddr.IPPortFrom(i, port)
}

func isCtxExtraPaddingRequired(traceFsPath string) bool {
	f, err := os.Open(path.Join(traceFsPath, "events/task/task_newtask/format"))
	if err != nil {
		klog.Errorln(err)
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		klog.Errorln(err)
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "common_preempt_lazy_count") {
			return true
		}
	}
	return false
}

const nfConntrackEventsParameterPath = "/proc/sys/net/netfilter/nf_conntrack_events"

func ensureConntrackEventsAreEnabled() error {
	v, err := common.ReadUintFromFile(nfConntrackEventsParameterPath)
	if err != nil {
		if common.IsNotExist(err) {
			klog.Warningf(
				"unable to check the value of %s, it appears that nf_conntrack is not loaded: %s",
				nfConntrackEventsParameterPath, err)
			return nil
		}
		return err
	}
	if v != 1 {
		klog.Infof("%s = %d, setting to 1", nfConntrackEventsParameterPath, v)
		if err = os.WriteFile(nfConntrackEventsParameterPath, []byte("1"), 0644); err != nil {
			return err
		}
	}
	return nil
}
