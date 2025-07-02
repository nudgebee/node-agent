package ebpftracer

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
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

const MaxPayloadSize = 1024 * 5

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

type ConnectionId struct {
	FD  uint64
	PID uint32
	_   uint32
}

type Connection struct {
	Timestamp     uint64
	BytesSent     uint64
	BytesReceived uint64
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
		{name: "python_thread_events", typ: perfMapTypePythonThreadEvents, perCPUBufferSizePages: 4},
	}

	if !t.disableL7Tracing {
		// Reduced buffer size for better cache performance
		// 16 pages = 64KB per CPU (down from 128KB)
		perfMaps = append(perfMaps, perfMap{name: "l7_events", typ: perfMapTypeL7Events, perCPUBufferSizePages: 16})
	}

	pageSize := os.Getpagesize()
	for _, pm := range perfMaps {
		// Optimized wake-up frequency: fewer interrupts, better batching
		wakeupEvents := 100
		if pm.name == "l7_events" {
			wakeupEvents = 50 // Less frequent wakeups for L7 events to reduce CPU overhead
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
			if strings.HasPrefix(programSpec.SectionName, "uprobe/") {
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

	return nil
}

// isValidHTTPData performs basic validation to detect garbage data in HTTP payloads
func isValidHTTPData(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	
	// Check for common HTTP methods (case-sensitive)
	httpMethods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "CONN", "OPTI", "PATC"}
	for _, method := range httpMethods {
		if len(data) >= len(method) && string(data[:len(method)]) == method {
			return true
		}
	}
	
	// Check for HTTP response (starts with "HTTP/")
	if len(data) >= 5 && string(data[:5]) == "HTTP/" {
		return true
	}
	
	// Check for printable ASCII characters (basic heuristic)
	nonPrintable := 0
	for i := 0; i < min(len(data), 100); i++ { // Check first 100 bytes
		if data[i] < 32 || data[i] > 126 {
			nonPrintable++
		}
	}
	
	// If more than 50% non-printable, likely garbage
	return float64(nonPrintable)/float64(min(len(data), 100)) < 0.5
}

// isResponseTruncated checks if a response appears to be incomplete
func isResponseTruncated(data []byte, protocol l7.Protocol) bool {
	if len(data) == 0 {
		return false
	}
	
	switch protocol {
	case l7.ProtocolHTTP:
		// Check if HTTP response ends abruptly
		dataStr := string(data)
		
		// Look for complete HTTP response indicators
		if strings.Contains(dataStr, "Content-Length:") {
			// TODO: Parse Content-Length and verify actual length
			// For now, assume truncation if data ends without proper closure
			return !strings.HasSuffix(strings.TrimSpace(dataStr), "}")  && 
				   !strings.HasSuffix(strings.TrimSpace(dataStr), "</html>") &&
				   !strings.HasSuffix(strings.TrimSpace(dataStr), "</body>") &&
				   len(data) >= 5120 // Near max payload size
		}
		
		// Check for chunked encoding completion
		if strings.Contains(dataStr, "Transfer-Encoding: chunked") {
			return !strings.Contains(dataStr, "\r\n0\r\n\r\n") // Final chunk marker
		}
		
	case l7.ProtocolHTTP2:
		// For HTTP/2, check if we have incomplete frames
		if len(data) < 9 {
			return true // Need at least frame header
		}
		
		// Basic HTTP/2 frame validation
		frameLength := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		if len(data) < int(frameLength)+9 {
			return true // Incomplete frame
		}
	}
	
	return false
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
}

type pythonThreadEvent struct {
	Type     EventType
	Pid      uint32
	Duration uint64
}

func runEventsReader(name string, r *perf.Reader, ch chan<- Event, typ perfMapType, readTimeout time.Duration) {
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
			klog.Errorln(name, "lost samples:", rec.LostSamples)
			continue
		}
		var event Event

		switch typ {
		case perfMapTypeL7Events:
			v := &l7Event{}
			data := rec.RawSample
			reader := bytes.NewBuffer(data)

			// Ensure binary.Read does not fail before proceeding
			if err := binary.Read(reader, binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}

			payload := reader.Bytes()
			expectedSize := int(v.PayloadSize) + int(v.ResponseSize)

			// Validate payload and response sizes to prevent garbage data
			if v.PayloadSize > 5120 || v.ResponseSize > 5120 { // MAX_PAYLOAD_SIZE = 5120
				klog.Warningf("Suspiciously large payload/response sizes: payload=%d, response=%d, skipping", v.PayloadSize, v.ResponseSize)
				continue
			}

			// If the actual payload is smaller than expected, we log a warning and adjust
			if len(payload) < expectedSize {
				klog.Warningf("Payload too small (got %d bytes, expected %d), adjusting sizes", len(payload), expectedSize)
			}

			// Compute safe slicing limits
			payloadEnd := min(int(v.PayloadSize), len(payload))
			responseEnd := min(payloadEnd+int(v.ResponseSize), len(payload))

			// Sanity check: ensure indices are valid
			if payloadEnd < 0 || responseEnd < payloadEnd || responseEnd > len(payload) {
				klog.Warningf("Invalid payload indices: payloadEnd=%d, responseEnd=%d, len(payload)=%d, skipping", payloadEnd, responseEnd, len(payload))
				continue
			}

			// Always copy to prevent garbage data from reused buffers
			payloadData := make([]byte, payloadEnd)
			copy(payloadData, payload[:payloadEnd])

			responseData := make([]byte, responseEnd-payloadEnd)
			copy(responseData, payload[payloadEnd:responseEnd])

			// Basic sanity check for HTTP protocol - look for garbage data
			if l7.Protocol(v.Protocol) == l7.ProtocolHTTP && payloadEnd > 0 {
				if !isValidHTTPData(payloadData) {
					klog.Warningf("Detected potential garbage HTTP payload data, skipping")
					continue
				}
			}

			// Enhanced response size validation for multi-packet protocols
			if responseEnd-payloadEnd > 0 && (l7.Protocol(v.Protocol) == l7.ProtocolHTTP || l7.Protocol(v.Protocol) == l7.ProtocolHTTP2) {
				// For HTTP/HTTP2, check if response looks truncated
				if isResponseTruncated(responseData, l7.Protocol(v.Protocol)) {
					klog.V(2).Infof("Detected potentially truncated %s response, size: %d", l7.Protocol(v.Protocol).String(), len(responseData))
				}
			}

			req := &l7.RequestData{
				Protocol:     l7.Protocol(v.Protocol),
				Status:       l7.Status(v.Status),
				Duration:     time.Duration(v.Duration),
				Method:       l7.Method(v.Method),
				StatementId:  v.StatementId,
				PayloadSize:  v.PayloadSize,
				ResponseSize: v.ResponseSize,
				Payload:      payloadData,
				Response:     responseData,
			}

			event = Event{
				Type:      EventTypeL7Request,
				Pid:       v.Pid,
				Fd:        v.Fd,
				Timestamp: v.ConnectionTimestamp,
				L7Request: req,
			}
		case perfMapTypeFileEvents:
			v := &fileEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Pid: v.Pid, Fd: v.Fd, Mnt: v.Mnt, Log: v.Log > 0}
		case perfMapTypeProcEvents:
			v := &procEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{Type: v.Type, Reason: EventReason(v.Reason), Pid: v.Pid}
		case perfMapTypeTCPEvents:
			v := &tcpEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{
				Type:          v.Type,
				Pid:           v.Pid,
				SrcAddr:       ipPort(v.SAddr, v.SPort),
				DstAddr:       ipPort(v.DAddr, v.DPort),
				ActualDstAddr: ipPort(v.AAddr, v.Aport),
				Fd:            v.Fd,
				Timestamp:     v.Timestamp,
				Duration:      time.Duration(v.Duration),
			}
			if v.Type == EventTypeConnectionClose {
				event.TrafficStats = &TrafficStats{
					BytesSent:     v.BytesSent,
					BytesReceived: v.BytesReceived,
				}
			}
		case perfMapTypePythonThreadEvents:
			v := &pythonThreadEvent{}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, v); err != nil {
				klog.Warningln("failed to read msg:", err)
				continue
			}
			event = Event{
				Type:     v.Type,
				Pid:      v.Pid,
				Duration: time.Duration(v.Duration),
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
