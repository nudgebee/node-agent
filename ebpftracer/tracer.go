package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
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
	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const MaxPayloadSize = 4096

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
	EventTypeHTTPFragment     EventType = 12

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
	HTTPFragment  *HTTPResponseFragment
	TrafficStats  *TrafficStats
	Mnt           uint64
	Log           bool
}

// HTTP response fragment data
type HTTPResponseFragment struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	FragmentId          uint32
	TotalExpected       uint32
	FragmentSize        uint16
	IsFinal             bool
	HttpStatus          uint16
	Data                []byte
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
	hostNetNs        netns.NsHandle
	selfNetNs        netns.NsHandle

	collection *ebpf.Collection
	readers    map[string]*perf.Reader
	links      []link.Link
	uprobes    map[string]*ebpf.Program
}

func NewTracer(hostNetNs, selfNetNs netns.NsHandle, disableL7Tracing bool) *Tracer {
	if disableL7Tracing {
		klog.Infoln("L7 tracing is disabled")
	}
	return &Tracer{
		disableL7Tracing: disableL7Tracing,
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
	return nil
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
	t.collection.Close()
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

func (t *Tracer) ebpf(ch chan<- Event) error {
	if _, ok := ebpfProgs[runtime.GOARCH]; !ok {
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	var traceFsPath string
	for _, p := range []string{"/sys/kernel/debug/tracing", "/sys/kernel/tracing"} {
		if _, err := os.Stat(p); err == nil {
			traceFsPath = p
			break
		}
	}
	if traceFsPath == "" {
		return fmt.Errorf("kernel tracing is not available: debugfs or tracefs must be mounted")
	}

	var flags string
	if isCtxExtraPaddingRequired(traceFsPath) {
		flags = "ctx-extra-padding"
	}
	kv := common.GetKernelVersion()
	var prog []byte
	for _, p := range ebpfProgs[runtime.GOARCH] {
		pv, _ := common.VersionFromString(p.version)
		if !kv.GreaterOrEqual(pv) {
			continue
		}
		if flags != p.flags {
			continue
		}
		prog = p.prog
		break
	}
	if len(prog) == 0 {
		return fmt.Errorf("unsupported kernel version: %s %s", kv, flags)
	}

	reader, err := gzip.NewReader(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(prog)))
	if err != nil {
		return fmt.Errorf("invalid program encoding: %w", err)
	}
	prog, err = io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to ungzip program: %w", err)
	}
	collectionSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return fmt.Errorf("failed to load collection spec: %w", err)
	}
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

	perfMaps := []perfMap{
		{name: "proc_events", typ: perfMapTypeProcEvents, perCPUBufferSizePages: 4},
		{name: "tcp_listen_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "tcp_connect_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 8, readTimeout: 10 * time.Millisecond},
		{name: "tcp_retransmit_events", typ: perfMapTypeTCPEvents, perCPUBufferSizePages: 4},
		{name: "file_events", typ: perfMapTypeFileEvents, perCPUBufferSizePages: 4},
	}

	if !t.disableL7Tracing {
		perfMaps = append(perfMaps, perfMap{name: "l7_events", typ: perfMapTypeL7Events, perCPUBufferSizePages: 128}) // Increased for high-volume LLM API tracing
	}

	pageSize := os.Getpagesize()
	for _, pm := range perfMaps {
		wakeupEvents := 100
		if pm.typ == perfMapTypeL7Events {
			wakeupEvents = 50 // Process L7 events more frequently to reduce buffer pressure
		}
		r, err := perf.NewReaderWithOptions(t.collection.Maps[pm.name], pm.perCPUBufferSizePages*pageSize, perf.ReaderOptions{WakeupEvents: wakeupEvents})
		if err != nil {
			t.Close()
			return fmt.Errorf("failed to create ebpf reader: %w", err)
		}
		t.readers[pm.name] = r
		go runEventsReader(pm.name, r, ch, pm.typ, pm.readTimeout)
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

func (t EventType) String() string {
	switch t {
	case EventTypeProcessStart:
		return "process-start"
	case EventTypeProcessExit:
		return "process-exit"
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

// HTTP response fragment event (must match eBPF struct)
type httpResponseFragment struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	FragmentId          uint32
	TotalExpected       uint32
	FragmentSize        uint16
	IsFinal             uint8
	HttpStatus          uint8
	Data                [2048]byte // Must match HTTP_FRAGMENT_SIZE in eBPF
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
	return tracker.(*lostSamplesTracker)
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
			var err error
			event, err = parseL7Event(rec.RawSample)
			if err != nil {
				klog.Warningln("failed to parse l7 event:", err)
				continue
			}
		case perfMapTypeFileEvents:
			var err error
			event, err = parseFileEvent(rec.RawSample)
			if err != nil {
				klog.Warningln("failed to parse file event:", err)
				continue
			}
		case perfMapTypeProcEvents:
			var err error
			event, err = parseProcEvent(rec.RawSample)
			if err != nil {
				klog.Warningln("failed to parse proc event:", err)
				continue
			}
		case perfMapTypeTCPEvents:
			var err error
			event, err = parseTCPEvent(rec.RawSample)
			if err != nil {
				klog.Warningln("failed to parse tcp event:", err)
				continue
			}
		default:
			continue
		}

		ch <- event
	}
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
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
