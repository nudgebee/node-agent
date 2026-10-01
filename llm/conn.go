package llm

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Direction is which way a captured chunk travelled, from the point of view
// of the application being observed.
type Direction uint8

const (
	Egress  Direction = iota // written by the application: requests
	Ingress                  // read by the application: responses
)

// Outcome classifies how a request, or a whole connection, ended up. It is
// what makes the capture's completeness measurable.
type Outcome string

const (
	// Per request.
	OutcomeCompleted   Outcome = "completed"   // usage extracted
	OutcomeNoUsage     Outcome = "no_usage"    // parsed, but the response carried no usage
	OutcomeUndecodable Outcome = "undecodable" // unsupported or corrupt Content-Encoding
	OutcomeTruncated   Outcome = "truncated"   // response body exceeded maxBody

	// Per connection.
	OutcomeMissedStart   Outcome = "missed_start"  // capture began mid-connection
	OutcomeUnrecoverable Outcome = "unrecoverable" // the parser lost the protocol framing
	OutcomeOverflow      Outcome = "overflow"      // the parser fell too far behind the capture
)

const (
	// maxBody caps the response body kept per request. Usage sits at the end
	// of a body, so a body cut short has lost it.
	maxBody = 8 << 20
	// maxBuffered caps unparsed bytes per direction.
	maxBuffered = 16 << 20
	// maxSkip caps zero-fill for bytes the kernel did not capture. Skipped
	// bytes are request bodies (prompts) too large to copy; past this size
	// the connection is not one worth reconstructing.
	maxSkip = 64 << 20
)

// Tag is why a connection is being captured.
type Tag struct {
	// Provider is set when the connection was identified by hostname, and
	// empty for an endpoint recognised only by its API paths (a gateway or a
	// self-hosted model server).
	Provider Provider
	// Host is the name the connection was identified by.
	Host string
}

// Exchange is one request/response on a captured connection.
type Exchange struct {
	// LLM is false for requests that are not LLM API calls (listing models,
	// uploading files). They are still reported, so HTTP metrics for the
	// connection stay complete.
	LLM bool

	Provider      Provider
	ServerAddress string
	Method        string
	Path          string
	StatusCode    int
	Operation     Operation
	Model         string
	Streaming     bool
	Usage         Usage
	Outcome       Outcome
	TraceParent   string

	// Kernel timestamps in nanoseconds.
	RequestStart uint64 // first byte of the request
	FirstData    uint64 // first byte of the response body
	ResponseEnd  uint64 // last byte of the response
}

func (e *Exchange) Duration() time.Duration {
	if e.ResponseEnd < e.RequestStart || e.RequestStart == 0 {
		return 0
	}
	return time.Duration(e.ResponseEnd - e.RequestStart)
}

// TimeToFirstToken is the time from the request to the first streamed byte of
// the response body. It is zero for non-streaming responses.
func (e *Exchange) TimeToFirstToken() time.Duration {
	if !e.Streaming || e.FirstData < e.RequestStart || e.RequestStart == 0 {
		return 0
	}
	return time.Duration(e.FirstData - e.RequestStart)
}

type connState uint8

const (
	stateNew connState = iota
	stateHTTP1
	stateHTTP2
	stateDead
)

// Conn reassembles one captured connection. Feed it chunks in capture order;
// it calls onExchange for every completed request, from its own goroutines.
type Conn struct {
	tag        Tag
	onExchange func(*Exchange)
	onOutcome  func(Outcome)

	mu          sync.Mutex
	state       connState
	missedStart bool
	egress      *stream
	ingress     *stream

	// HTTP/1.1: requests waiting for their response, in order.
	requests chan *request
	// HTTP/2: streams by id.
	streams map[uint32]*h2stream
}

type request struct {
	method, path, host, traceParent string
	start                           uint64
}

func NewConn(tag Tag, onExchange func(*Exchange), onOutcome func(Outcome)) *Conn {
	return &Conn{
		tag:        tag,
		onExchange: onExchange,
		onOutcome:  onOutcome,
		egress:     newStream(maxBuffered),
		ingress:    newStream(maxBuffered),
	}
}

// Feed appends a captured chunk. skipped is the number of bytes the kernel
// dropped immediately before this chunk.
func (c *Conn) Feed(dir Direction, data []byte, ts uint64, skipped uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case stateDead:
		return
	case stateNew:
		if dir != Egress {
			return // a response with no request seen: wait for the next request
		}
		switch {
		case skipped == 0 && bytes.HasPrefix(data, []byte(http2.ClientPreface)):
			c.state = stateHTTP2
			c.streams = map[uint32]*h2stream{}
			go c.h2Egress()
			go c.h2Ingress()
		case skipped == 0 && looksLikeRequestLine(data):
			c.state = stateHTTP1
			c.requests = make(chan *request, 64)
			go c.h1Requests()
			go c.h1Responses()
		case len(data) > 1 && data[0] >= 0x14 && data[0] <= 0x17 && data[1] == 0x03:
			// TLS records: a connection marked by destination is captured
			// from its first write, which for HTTPS is the handshake. The
			// plaintext follows once the TLS library takes over.
			return
		default:
			// Capture started mid-connection. HTTP/1.1 recovers at the next
			// request; HTTP/2 never does, since its header compression state is
			// lost, so this keeps waiting harmlessly until the connection closes.
			if !c.missedStart {
				c.missedStart = true
				c.report(OutcomeMissedStart)
			}
			return
		}
	}
	s := c.egress
	if dir == Ingress {
		s = c.ingress
	}
	if skipped > 0 {
		if skipped > maxSkip {
			c.failLocked(OutcomeUnrecoverable)
			return
		}
		// Zero-fill keeps the framing of length-delimited bodies intact.
		if !s.write(make([]byte, skipped), ts) {
			c.failLocked(OutcomeOverflow)
			return
		}
	}
	if !s.write(data, ts) {
		c.failLocked(OutcomeOverflow)
	}
}

// Close releases the connection's goroutines.
func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != stateDead {
		c.state = stateDead
	}
	c.egress.close()
	c.ingress.close()
}

func (c *Conn) fail(o Outcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failLocked(o)
}

func (c *Conn) failLocked(o Outcome) {
	if c.state == stateDead {
		return
	}
	c.state = stateDead
	c.egress.close()
	c.ingress.close()
	c.report(o)
}

func (c *Conn) report(o Outcome) {
	if c.onOutcome != nil {
		c.onOutcome(o)
	}
}

var requestMethods = []string{"POST ", "GET ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "}

func looksLikeRequestLine(b []byte) bool {
	for _, m := range requestMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// --- HTTP/1.1 ---

func (c *Conn) h1Requests() {
	br := bufio.NewReaderSize(c.egress, 16<<10)
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		start := c.egress.tsAt(c.egress.consumed(br))
		req, err := http.ReadRequest(br)
		if err != nil {
			c.fail(OutcomeUnrecoverable)
			return
		}
		r := &request{
			method:      req.Method,
			path:        req.URL.RequestURI(),
			host:        req.Host,
			traceParent: req.Header.Get("Traceparent"),
			start:       start,
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		select {
		case c.requests <- r:
		default:
			// Responses have stopped arriving; nothing will pair with this.
		}
	}
}

func (c *Conn) h1Responses() {
	br := bufio.NewReaderSize(c.ingress, 16<<10)
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			c.fail(OutcomeUnrecoverable)
			return
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			continue // 100 Continue and friends precede the real response
		}
		var req *request
		select {
		case req = <-c.requests:
		case <-time.After(time.Second):
			req = &request{}
		}
		var firstData uint64
		body := &bytes.Buffer{}
		truncated := false
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if firstData == 0 {
					firstData = c.ingress.tsAt(c.ingress.consumed(br) - 1)
				}
				if body.Len()+n > maxBody {
					truncated = true
				} else {
					body.Write(buf[:n])
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					_ = resp.Body.Close()
					c.fail(OutcomeUnrecoverable)
					return
				}
				break
			}
		}
		_ = resp.Body.Close()
		end := c.ingress.tsAt(c.ingress.consumed(br) - 1)
		c.finish(req, resp.StatusCode, resp.Header, body.Bytes(), firstData, end, truncated)
	}
}

// --- HTTP/2 ---

type h2stream struct {
	req       *request
	status    int
	header    http.Header
	body      bytes.Buffer
	truncated bool
	firstData uint64
	end       uint64
	done      bool // the response has ended
}

// newHPACKDecoder starts at the protocol's 4096-byte table, which is what the
// peer's encoder starts at too. The allowed maximum is raised so a peer that
// advertised a larger table can grow into it without an error.
func newHPACKDecoder() *hpack.Decoder {
	d := hpack.NewDecoder(4096, nil)
	d.SetAllowedMaxDynamicTableSize(1 << 20)
	return d
}

func newFramer(r io.Reader) *http2.Framer {
	fr := http2.NewFramer(nil, r)
	fr.SetMaxReadFrameSize(1<<24 - 1)
	fr.ReadMetaHeaders = newHPACKDecoder()
	fr.MaxHeaderListSize = 1 << 20
	return fr
}

// frameStart is the stream offset of the frame just read.
func frameStart(s *stream, h http2.FrameHeader) uint64 {
	return s.offset() - uint64(9+h.Length)
}

func (c *Conn) h2Egress() {
	if _, err := io.ReadFull(c.egress, make([]byte, len(http2.ClientPreface))); err != nil {
		return
	}
	fr := newFramer(c.egress)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if c.h2ReadError(err) {
				continue
			}
			return
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			// The client gave up on the stream (a cancelled context): the
			// server will not finish it, so it ends here.
			c.mu.Lock()
			if s := c.streams[rst.StreamID]; s != nil && !s.done {
				s.done, s.end = true, c.egress.tsAt(frameStart(c.egress, rst.Header()))
			}
			c.mu.Unlock()
			c.h2MaybeFinish(rst.StreamID)
			continue
		}
		mh, ok := f.(*http2.MetaHeadersFrame)
		if !ok {
			continue
		}
		r := &request{
			method:      mh.PseudoValue("method"),
			path:        mh.PseudoValue("path"),
			host:        mh.PseudoValue("authority"),
			traceParent: headerValue(mh, "traceparent"),
			start:       c.egress.tsAt(frameStart(c.egress, mh.Header())),
		}
		c.mu.Lock()
		s := c.streamLocked(mh.StreamID)
		s.req = r
		c.mu.Unlock()
		c.h2MaybeFinish(mh.StreamID)
	}
}

func (c *Conn) h2Ingress() {
	fr := newFramer(c.ingress)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			if c.h2ReadError(err) {
				continue
			}
			return
		}
		ts := c.ingress.tsAt(frameStart(c.ingress, f.Header()))
		id := f.Header().StreamID
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			c.mu.Lock()
			s := c.streamLocked(id)
			if s.status == 0 {
				s.status = statusOf(f)
				s.header = make(http.Header)
				for _, hf := range f.RegularFields() {
					s.header.Add(hf.Name, hf.Value)
				}
			}
			if f.StreamEnded() {
				s.done, s.end = true, ts
			}
			c.mu.Unlock()
		case *http2.DataFrame:
			c.mu.Lock()
			s := c.streamLocked(id)
			if data := f.Data(); len(data) > 0 {
				if s.firstData == 0 {
					s.firstData = ts
				}
				if s.body.Len()+len(data) > maxBody {
					s.truncated = true
				} else {
					s.body.Write(data)
				}
			}
			if f.StreamEnded() {
				s.done, s.end = true, ts
			}
			c.mu.Unlock()
		case *http2.RSTStreamFrame:
			c.mu.Lock()
			s := c.streamLocked(id)
			s.done, s.end = true, ts
			c.mu.Unlock()
		default:
			continue
		}
		c.h2MaybeFinish(id)
	}
}

// h2ReadError reports whether reading can continue after err. A stream error
// spoils one request; anything else means the framing is lost.
func (c *Conn) h2ReadError(err error) bool {
	var se http2.StreamError
	if errors.As(err, &se) {
		return true
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		c.fail(OutcomeUnrecoverable)
	}
	return false
}

func (c *Conn) streamLocked(id uint32) *h2stream {
	s := c.streams[id]
	if s == nil {
		s = &h2stream{}
		c.streams[id] = s
	}
	return s
}

// h2MaybeFinish completes a stream once both its request and the end of its
// response have been parsed. The two directions are parsed independently, so
// either may get there first.
func (c *Conn) h2MaybeFinish(id uint32) {
	c.mu.Lock()
	s := c.streams[id]
	if s == nil || !s.done || s.req == nil {
		c.mu.Unlock()
		return
	}
	delete(c.streams, id)
	c.mu.Unlock()
	c.finish(s.req, s.status, s.header, s.body.Bytes(), s.firstData, s.end, s.truncated)
}

func statusOf(f *http2.MetaHeadersFrame) int {
	v := f.PseudoValue("status")
	n := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func headerValue(f *http2.MetaHeadersFrame, name string) string {
	for _, hf := range f.RegularFields() {
		if hf.Name == name {
			return hf.Value
		}
	}
	return ""
}

// --- completion ---

func (c *Conn) finish(req *request, status int, header http.Header, body []byte, firstData, end uint64, truncated bool) {
	if header == nil {
		header = http.Header{}
	}
	e := &Exchange{
		Provider:      c.tag.Provider,
		ServerAddress: c.tag.Host,
		Method:        req.method,
		Path:          req.path,
		StatusCode:    status,
		TraceParent:   req.traceParent,
		RequestStart:  req.start,
		FirstData:     firstData,
		ResponseEnd:   end,
	}
	if e.ServerAddress == "" {
		e.ServerAddress = req.host
	}
	if e.Provider == "" {
		e.Provider = ProviderCompatible
	}
	r, ok := classifyPath(req.path)
	e.LLM = ok
	e.Operation, e.Model = r.operation, r.model
	ct := strings.ToLower(header.Get("Content-Type"))
	e.Streaming = r.streaming || strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "vnd.amazon.eventstream")

	switch {
	case !ok:
	case truncated:
		e.Outcome = OutcomeTruncated
	default:
		decoded, err := decodeBody(header.Get("Content-Encoding"), body)
		if err != nil {
			e.Outcome = OutcomeUndecodable
			break
		}
		model, u, found := extractUsage(r.family, header, decoded)
		if e.Model == "" {
			e.Model = model
		}
		e.Usage = u
		e.Outcome = OutcomeNoUsage
		if found {
			e.Outcome = OutcomeCompleted
		}
	}
	if c.onExchange != nil {
		c.onExchange(e)
	}
}
