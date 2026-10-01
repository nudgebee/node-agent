package containers

import (
	"fmt"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/ebpftracer"
	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/coroot/coroot-node-agent/llm"
	"github.com/coroot/coroot-node-agent/tracing"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	// Close events arrive on a different buffer than captured data, so the
	// last chunks of a connection can be processed after its close.
	llmCaptureGrace = 5 * time.Second
	// A capture whose close was never seen is released after this long idle.
	llmCaptureIdle             = 30 * time.Minute
	maxLLMCapturesPerContainer = 1024
)

// llmCapture is a connection identified as an LLM API connection, whose
// byte stream the kernel copies to userspace in full.
type llmCapture struct {
	conn *llm.Conn
	// ts is the kernel's timestamp for the connection, which tells it apart
	// from a later connection that reuses the fd. 0 until the kernel has one.
	ts       uint64
	lastData time.Time
	closedAt time.Time
}

// startLLMCapture begins capturing a connection identified by the hostname in
// its TLS ClientHello. Called with c.lock held.
func (c *Container) startLLMCapture(pid uint32, fd uint64, ts uint64, tag llm.Tag) {
	pidFd := PidFd{Pid: pid, Fd: fd}
	if old := c.llmCaptures[pidFd]; old != nil {
		old.conn.Close()
		delete(c.llmCaptures, pidFd)
	}
	if len(c.llmCaptures) >= maxLLMCapturesPerContainer {
		LLMCaptureTotal.WithLabelValues("capacity").Inc()
		return
	}
	if err := c.registry.tracer.TagLLMConnection(pid, fd, ts); err != nil {
		klog.Warningf("failed to mark pid=%d fd=%d for LLM capture: %v", pid, fd, err)
		return
	}
	c.newLLMCapture(pid, fd, ts, tag)
	LLMCaptureTotal.WithLabelValues("tagged").Inc()
	klog.V(2).Infof("LLM capture started: pid=%d fd=%d host=%s provider=%s", pid, fd, tag.Host, tag.Provider)
}

// newLLMCapture sets up userspace for a connection the kernel captures.
// Called with c.lock held.
func (c *Container) newLLMCapture(pid uint32, fd uint64, ts uint64, tag llm.Tag) {
	pidFd := PidFd{Pid: pid, Fd: fd}
	lc := &llmCapture{ts: ts, lastData: time.Now()}
	lc.conn = llm.NewConn(tag,
		func(e *llm.Exchange) { c.onLLMExchange(pidFd, e) },
		func(o llm.Outcome) { LLMCaptureTotal.WithLabelValues(string(o)).Inc() },
	)
	c.llmCaptures[pidFd] = lc
}

// feedLLMCapture hands a chunk of a captured connection to its parser, and
// reports whether the connection is being captured. Called with c.lock held.
func (c *Container) feedLLMCapture(pid uint32, fd uint64, ts uint64, ingress bool, data []byte, at uint64, skipAfter uint64) bool {
	lc := c.llmCaptures[PidFd{Pid: pid, Fd: fd}]
	if lc == nil {
		return false
	}
	switch {
	case lc.ts == 0:
		lc.ts = ts
	case ts != 0 && ts != lc.ts:
		return false
	}
	dir := llm.Egress
	if ingress {
		dir = llm.Ingress
	}
	lc.conn.Feed(dir, data, at, 0)
	if skipAfter > 0 {
		lc.conn.Feed(dir, nil, at, skipAfter)
	}
	lc.lastData = time.Now()
	return true
}

func (c *Container) onLLMData(e ebpftracer.Event) {
	d := e.LLMData
	c.lock.Lock()
	defer c.lock.Unlock()
	pidFd := PidFd{Pid: e.Pid, Fd: e.Fd}
	lc := c.llmCaptures[pidFd]
	if lc != nil && lc.ts != 0 && e.Timestamp != 0 && lc.ts != e.Timestamp {
		// A newer connection on a reused fd, while the old one's capture
		// is still in its grace period. The kernel's timestamp is the
		// authority on which connection this is.
		lc.conn.Close()
		delete(c.llmCaptures, pidFd)
		lc = nil
	}
	if lc == nil {
		// The kernel marked this connection itself, because its destination
		// is a known LLM endpoint (tagLLMDestination). The provider and host
		// come from the requests.
		if len(c.llmCaptures) >= maxLLMCapturesPerContainer {
			LLMCaptureTotal.WithLabelValues("capacity").Inc()
			return
		}
		c.newLLMCapture(e.Pid, e.Fd, e.Timestamp, llm.Tag{})
		LLMCaptureTotal.WithLabelValues("tagged_destination").Inc()
	}
	c.feedLLMCapture(e.Pid, e.Fd, e.Timestamp, d.Ingress, d.Data, d.Time, d.SkipAfter)
}

// detectLLMEndpoint recognises an LLM API request on a connection that was
// not identified by its TLS ClientHello: a gateway or self-hosted model
// server reached over plain HTTP, or a keep-alive connection opened before
// the agent started. The request itself has gone by; the rest of the
// connection is captured. It works from the request bytes and the socket
// tuple alone, ahead of connection tracking, which short-lived connections
// often outrun. Called with c.lock held.
func (c *Container) detectLLMEndpoint(pid uint32, fd uint64, ts uint64, r *l7.RequestData, si *ebpftracer.SocketInfo) {
	if r.Protocol != l7.ProtocolHTTP {
		return
	}
	path, host := llm.RequestPathAndHost(r.Payload)
	if !llm.IsAPIPath(path) {
		return
	}
	provider, _ := llm.ProviderForHost(host)
	c.startLLMCapture(pid, fd, ts, llm.Tag{Provider: provider, Host: stripPort(host)})
	// Clients of gateways often open a connection per request, so the
	// destination is marked too and the kernel captures every new connection
	// to it from its first write. Only for plain HTTP: a TLS endpoint has a
	// hostname of its own, and an HTTPS address can be a shared front end.
	if r.TLS || si == nil || !si.Valid {
		return
	}
	ip, err := netaddr.ParseIP(si.DstIP)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s:%d", si.DstIP, si.DstPort)
	if _, done := c.registry.llmDestinations.LoadOrStore(key, struct{}{}); done {
		return
	}
	if err := c.registry.tracer.TagLLMDestination(ip, si.DstPort); err != nil {
		klog.Warningf("failed to mark %s as an LLM endpoint: %v", key, err)
		c.registry.llmDestinations.Delete(key)
		return
	}
	klog.Infof("LLM endpoint detected: %s (path %s, host %s); capturing new connections to it", key, path, host)
}

// feedLLMCaptureFromL7 routes a generic L7 event of a captured connection.
// The kernel only starts copying a connection once userspace has marked it,
// so its first frames take the generic path; they arrive in order with the
// copied chunks, and are spliced into the same stream here. Called with
// c.lock held.
func (c *Container) feedLLMCaptureFromL7(pid uint32, fd uint64, ts uint64, r *l7.RequestData) bool {
	if c.llmCaptures[PidFd{Pid: pid, Fd: fd}] == nil {
		return false
	}
	skipped := func(size uint64, have int) uint64 {
		if size > uint64(have) {
			return size - uint64(have)
		}
		return 0
	}
	at := r.KernelTime
	switch {
	case r.Protocol == l7.ProtocolHTTP2 && r.Method == l7.MethodHttp2ClientFrames:
		return c.feedLLMCapture(pid, fd, ts, false, r.Payload, at, skipped(r.PayloadSize, len(r.Payload)))
	case r.Protocol == l7.ProtocolHTTP2 && r.Method == l7.MethodHttp2ServerFrames:
		return c.feedLLMCapture(pid, fd, ts, true, r.Payload, at, skipped(r.PayloadSize, len(r.Payload)))
	case r.Protocol == l7.ProtocolHTTP:
		// A request and the first read of its response, delivered together
		// when the response arrived, r.Duration after the request.
		resp := monotonicNow()
		req := resp - uint64(r.Duration)
		c.feedLLMCapture(pid, fd, ts, false, r.Payload, req, skipped(r.PayloadSize, len(r.Payload)))
		return c.feedLLMCapture(pid, fd, ts, true, r.Response, resp, skipped(r.ResponseSize, len(r.Response)))
	}
	return true
}

// closeLLMCapture schedules the release of a captured connection. ts guards
// against a close of an earlier connection on the same fd, whose event can be
// processed after a capture of the next one has started. Called with c.lock
// held.
func (c *Container) closeLLMCapture(pid uint32, fd uint64, ts uint64) {
	pidFd := PidFd{Pid: pid, Fd: fd}
	lc := c.llmCaptures[pidFd]
	if lc == nil || !lc.closedAt.IsZero() || (lc.ts != 0 && ts != 0 && lc.ts != ts) {
		return
	}
	lc.closedAt = time.Now()
	// Released on a timer rather than at the next gc: a response delimited
	// by the connection closing only ends when its stream does.
	time.AfterFunc(llmCaptureGrace, func() {
		c.lock.Lock()
		defer c.lock.Unlock()
		if c.llmCaptures[pidFd] == lc {
			lc.conn.Close()
			delete(c.llmCaptures, pidFd)
		}
	})
}

// gcLLMCaptures releases captures that are closed, idle, or whose process is
// gone. Called with c.lock held.
func (c *Container) gcLLMCaptures(now time.Time) {
	for pidFd, lc := range c.llmCaptures {
		_, alive := c.processes[pidFd.Pid]
		if !alive || (!lc.closedAt.IsZero() && now.Sub(lc.closedAt) > llmCaptureGrace) || now.Sub(lc.lastData) > llmCaptureIdle {
			lc.conn.Close()
			delete(c.llmCaptures, pidFd)
		}
	}
}

func (c *Container) closeAllLLMCaptures() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for pidFd, lc := range c.llmCaptures {
		lc.conn.Close()
		delete(c.llmCaptures, pidFd)
	}
}

// onLLMExchange records a completed request on a captured connection. It runs
// on the connection's parser goroutines.
func (c *Container) onLLMExchange(pidFd PidFd, e *llm.Exchange) {
	traceID, parentSpanID := parseTraceParent(e.TraceParent)
	if e.LLM {
		recordLLMExchange(string(c.id), e)
	}

	// The kernel no longer sends this connection's events down the generic
	// path, so its HTTP metrics come from here.
	var destination common.DestinationKey
	var src common.Workload
	found := false
	c.lock.Lock()
	if conn := c.connectionsByPidFd[pidFd]; conn != nil {
		destination, src, found = conn.DestinationKey, conn.srcWorkload, true
		r := &l7.RequestData{Protocol: l7.ProtocolHTTP, Status: l7.Status(e.StatusCode), Duration: e.Duration()}
		c.l7Stats.observe(l7.ProtocolHTTP, r.Status.Http(), e.Method, e.Path, e.Duration(), destination, src, r, traceID)
	}
	c.lock.Unlock()

	if !e.LLM || c.tracer == nil || !found {
		return
	}
	dst := common.Workload{Name: e.ServerAddress}
	trace := c.tracer.NewTrace(destination.Destination(), src, dst, dst)
	if trace == nil {
		return
	}
	var firstToken time.Time
	if e.TimeToFirstToken() > 0 {
		firstToken = kernelTime(e.FirstData)
	}
	trace.LLMRequest(tracing.LLMStreamInfo{
		Provider:       string(e.Provider),
		Model:          e.Model,
		Operation:      string(e.Operation),
		ServerAddress:  e.ServerAddress,
		TraceID:        traceID,
		ParentSpanID:   parentSpanID,
		RequestTime:    kernelTime(e.RequestStart),
		FirstTokenTime: firstToken,
		CompletionTime: kernelTime(e.ResponseEnd),
		InputTokens:    int(e.Usage.Input + e.Usage.CachedInput + e.Usage.CacheWrite),
		OutputTokens:   int(e.Usage.Output + e.Usage.Reasoning),
		StatusCode:     e.StatusCode,
		IsError:        e.StatusCode >= 400,
	})
}

// parseTraceParent splits a W3C traceparent header into trace and span ids.
func parseTraceParent(v string) (traceID, spanID string) {
	parts := strings.Split(v, "-")
	if len(parts) != 4 {
		return "", ""
	}
	return parts[1], parts[2]
}

func monotonicNow() uint64 {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return 0
	}
	return uint64(ts.Nano())
}

// kernelTime converts a bpf_ktime_get_ns() value, which is CLOCK_MONOTONIC,
// to wall-clock time.
func kernelTime(ns uint64) time.Time {
	now := monotonicNow()
	if ns == 0 || now == 0 {
		return time.Time{}
	}
	if ns > now {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(now - ns))
}
