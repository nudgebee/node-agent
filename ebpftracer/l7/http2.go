package l7

import (
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"k8s.io/klog/v2"
)

// OnHPACKDecodeError is an optional callback invoked when the HTTP/2 parser
// fails to decode an HPACK header block. Wired from the containers package
// to a Prometheus counter so that the mid-stream-join failure mode is
// observable without needing to read agent logs.
var OnHPACKDecodeError func()

// OnHttp2Stage, if set, is invoked as a request advances through the parser.
// It exists so the pipeline can be measured stage by stage without l7 importing
// prometheus (same reason as OnHPACKDecodeError).
//
// External HTTP/2 enters at ~1.5M events per 10 minutes and leaves as zero
// completed requests; every step between those two numbers was previously
// unobservable, which meant diagnosing it one hypothesis and one deploy at a
// time. dest is the destination class ("external"/"internal") because that is
// the axis the failure splits on.
var OnHttp2Stage func(stage, dest string)

// OnHttp2Frame, if set, is invoked for each frame header the parser walks, and
// once with "invalid" when a header fails the type/length sanity check.
//
// This answers "are these bytes actually HTTP/2, and do they contain HEADERS?"
// without logging any payload. That distinction matters: these events carry
// decrypted application traffic, so a raw dump would put Authorization headers
// and request bodies into agent logs. Frame type, flags and length are
// structural metadata and disclose nothing.
var OnHttp2Frame func(frameType, dest string)

// http2FrameTypeName keeps the metric label bounded to the ten defined frame
// types plus "invalid"; h.Type is already range-checked by the caller.
func http2FrameTypeName(t http2.FrameType) string {
	switch t {
	case http2.FrameData:
		return "DATA"
	case http2.FrameHeaders:
		return "HEADERS"
	case http2.FramePriority:
		return "PRIORITY"
	case http2.FrameRSTStream:
		return "RST_STREAM"
	case http2.FrameSettings:
		return "SETTINGS"
	case http2.FramePushPromise:
		return "PUSH_PROMISE"
	case http2.FramePing:
		return "PING"
	case http2.FrameGoAway:
		return "GOAWAY"
	case http2.FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case http2.FrameContinuation:
		return "CONTINUATION"
	}
	return "invalid"
}

func (p *Http2Parser) frame(name string) {
	if OnHttp2Frame != nil {
		OnHttp2Frame(name, p.DestClass)
	}
}

func (p *Http2Parser) stage(name string) {
	if OnHttp2Stage != nil {
		OnHttp2Stage(name, p.DestClass)
	}
}

// safeKernelDuration computes the duration between two kernel timestamps,
// returning 0 if the result would underflow or exceed 1 hour.
func safeKernelDuration(end, start uint64) time.Duration {
	if end <= start {
		return 0
	}
	d := end - start
	if d >= uint64(time.Hour) {
		return 0
	}
	return time.Duration(d)
}

const (
	http2FrameHeaderLength = 9
	http2DecoderGcInterval = uint64(2 * time.Minute)

	// HTTP/2 flags
	http2FlagEndStream  = 0x01
	http2FlagEndHeaders = 0x04
	http2FlagPadded     = 0x08
	http2FlagPriority   = 0x20

	// Max accumulated header block size (64KB) to prevent unbounded growth
	maxPendingHeaderBlockSize = 64 * 1024

	// Max concurrent HTTP/2 streams tracked per connection.
	// Prevents unbounded memory growth when responses never complete (orphan
	// streams); at the limit the oldest stream makes way (evictOldestRequest).
	// It must exceed what one connection legitimately carries: gRPC clients
	// multiplex long-polls (workflow and job-queue workers' polls, which get
	// no response headers until the poll returns, up to a minute later) by
	// the hundred over one connection, and at 100 live polls were evicted.
	// Orphans are still reclaimed by the stream GC (http2DecoderGcInterval);
	// a request costs ~200 bytes, so a full table is ~200 KB.
	maxActiveRequests = 1000
)

type Http2FrameHeader struct {
	Type     http2.FrameType
	Flags    http2.Flags
	Length   int
	StreamId uint32
}

type Http2Request struct {
	Method      string
	Path        string
	Scheme      string
	Authority   string // :authority pseudo-header (hostname:port)
	ContentType string // content-type header (for gRPC detection)
	Status      Status
	GrpcStatus  Status
	Duration    time.Duration

	kernelTime uint64

	// Internal state for tracking stream completion
	hasResponseStatus bool // true when we've received :status in response HEADERS
	responseEndStream bool // true when we've received END_STREAM on response

	// PartialHeaders indicates HPACK decoding had errors (e.g., mid-stream join)
	// and some headers may be missing. Static table headers are still reliable.
	PartialHeaders bool
}

// pendingHeaderBlock tracks in-progress header block fragments for streams
// that sent HEADERS without END_HEADERS flag. Per HTTP/2 spec (RFC 9113 Section 4.3),
// CONTINUATION frames must follow until END_HEADERS is set.
type pendingHeaderBlock struct {
	streamId  uint32
	fragments []byte
	endStream bool // END_STREAM flag from the initial HEADERS frame
}

type Http2Parser struct {
	// ConnTimestamp records which connection this parser was created for.
	// Callers key parsers by pid+fd, which a recycled fd can collide on; this
	// lets them detect that case instead of silently decoding a new connection
	// with the previous one's HPACK dynamic table.
	ConnTimestamp uint64

	// DestClass labels stage counters ("external"/"internal"); set by the caller.
	DestClass string

	// sawValidFrame reports whether the most recent Parse call decoded at least
	// one structurally valid frame header. Callers use it to detect connections
	// the eBPF heuristic mistagged as HTTP/2: those yield nothing but invalid
	// frames, indefinitely, because the protocol is cached per connection.
	sawValidFrame bool

	clientDecoder  *hpackDecoder
	serverDecoder  *hpackDecoder
	activeRequests map[uint32]*Http2Request
	lastGcTime     uint64

	// Reusable maps cleared on each Parse() call to avoid per-call allocation
	statuses     map[uint32]Status
	grpcStatuses map[uint32]Status

	// Buffers for partial frame reassembly across Read() calls
	// Needed because S2A/TLS returns small chunks that may split HTTP/2 frames
	clientPartialFrame []byte
	serverPartialFrame []byte

	// Bytes still to skip at the start of the next read, per direction: the
	// rest of a frame the kernel cut short. See Parse.
	clientSkip uint64
	serverSkip uint64

	// Pending header block fragments for HEADERS + CONTINUATION reassembly
	// Only one pending header block can exist per direction at a time
	clientPendingHeaders *pendingHeaderBlock
	serverPendingHeaders *pendingHeaderBlock

	// Degraded mode: set when decoder was reset due to mid-stream join HPACK errors.
	// Static table headers still work; dynamic table rebuilds over time.
	clientDecoderDegraded bool
	serverDecoderDegraded bool
}

func NewHttp2Parser() *Http2Parser {
	return &Http2Parser{
		clientDecoder:  newHpackDecoder(),
		serverDecoder:  newHpackDecoder(),
		activeRequests: make(map[uint32]*Http2Request),
		statuses:       make(map[uint32]Status),
		grpcStatuses:   make(map[uint32]Status),
	}
}

// resetDecoder forgets a direction's HPACK dynamic table, when a header block
// was lost or decoded to garbage and the table can no longer be trusted to
// match the encoder's. The static table (indices 1-61) keeps working, and the
// decoder converges on the encoder's table again as new entries are inserted:
// see hpackDecoder.
func (p *Http2Parser) resetDecoder(method Method) {
	switch method {
	case MethodHttp2ClientFrames:
		p.clientDecoder.reset()
		p.clientDecoderDegraded = true
	case MethodHttp2ServerFrames:
		p.serverDecoder.reset()
		p.serverDecoderDegraded = true
	}
}

// Lost tells the parser that events of its connection were not delivered
// before the current one (l7.LostWrites: client frames, l7.LostReads: server
// frames). Nothing in the bytes shows the gap: a frame cut by it would be
// spliced onto unrelated bytes, and a header block in it took its HPACK
// insertions with it, so later references would decode to the wrong
// headers. That direction's partial frame and pending header block are
// dropped and its table reset.
func (p *Http2Parser) Lost(lost uint8) {
	if lost&LostWrites != 0 {
		p.clientPartialFrame, p.clientSkip, p.clientPendingHeaders = nil, 0, nil
		p.resetDecoder(MethodHttp2ClientFrames)
		p.stage("events_lost")
	}
	if lost&LostReads != 0 {
		p.serverPartialFrame, p.serverSkip, p.serverPendingHeaders = nil, 0, nil
		p.resetDecoder(MethodHttp2ServerFrames)
		p.stage("events_lost")
	}
}

// evictOldestRequest makes room for a new stream by dropping a request still
// waiting for its response.
//
// The streams that fill the table are mostly ones whose response the parser
// will never see: it was in a read cut short by truncation, or in an event
// lost before it. They are only collected after http2DecoderGcInterval.
// Refusing new streams until then dropped every request on a busy
// connection for minutes, silently. A request without response headers goes
// first, oldest first: one whose response was lost never gets them, while
// the oldest stream overall is often a live long-lived one (a watch, a
// bidirectional stream) that already has its headers and awaits its end.
func (p *Http2Parser) evictOldestRequest() {
	var victimId uint32
	var victim *Http2Request
	for id, r := range p.activeRequests {
		if victim == nil || evictsBefore(r, victim) {
			victimId, victim = id, r
		}
	}
	if victim != nil {
		delete(p.activeRequests, victimId)
		p.stage("stream_evicted")
	}
}

func evictsBefore(a, b *Http2Request) bool {
	if a.hasResponseStatus != b.hasResponseStatus {
		return !a.hasResponseStatus
	}
	return a.kernelTime < b.kernelTime
}

// dropPendingHeaders discards a header block still waiting for CONTINUATION
// frames. Its insertions never reach the table, so the table is reset too.
func (p *Http2Parser) dropPendingHeaders(method Method, pending **pendingHeaderBlock) {
	if *pending != nil {
		*pending = nil
		p.resetDecoder(method)
	}
}

// SawValidFrame reports whether the last Parse call decoded at least one
// structurally valid frame header.
func (p *Http2Parser) SawValidFrame() bool {
	return p.sawValidFrame
}

// ActiveRequestCount returns the number of HTTP/2 requests currently being tracked
// (waiting for response completion)
func (p *Http2Parser) ActiveRequestCount() int {
	return len(p.activeRequests)
}

// HasPartialData returns true if the parser has buffered partial frame data
// that would be lost if the parser were garbage collected.
func (p *Http2Parser) HasPartialData() bool {
	return len(p.clientPartialFrame) > 0 || len(p.serverPartialFrame) > 0 ||
		p.clientPendingHeaders != nil || p.serverPendingHeaders != nil
}

// extractHeaderBlockFragment extracts the HPACK data from a HEADERS frame payload,
// skipping the optional Pad Length, Priority, and Padding fields per RFC 9113 Section 6.2.
// CONTINUATION frames have no such fields -- their entire payload is HPACK data.
func extractHeaderBlockFragment(flags http2.Flags, framePayload []byte) []byte {
	offset := 0
	var padLength int

	if flags&http2FlagPadded != 0 {
		if len(framePayload) < 1 {
			return nil
		}
		padLength = int(framePayload[0])
		offset++
	}

	if flags&http2FlagPriority != 0 {
		// 4 bytes stream dependency + 1 byte weight = 5 bytes
		offset += 5
	}

	if offset > len(framePayload) {
		return nil
	}

	end := len(framePayload) - padLength
	if end < offset {
		return nil
	}

	return framePayload[offset:end]
}

// decodeHeaderBlock processes a complete HPACK-encoded header block for a stream.
func (p *Http2Parser) decodeHeaderBlock(
	method Method,
	streamId uint32,
	endStream bool,
	hpackData []byte,
	decoder *hpackDecoder,
	statuses map[uint32]Status,
	grpcStatuses map[uint32]Status,
	kernelTime uint64,
) {
	// implausible is set when the block decodes to pseudo-headers that cannot
	// be right for its direction: a sign the dynamic table has drifted from
	// the encoder's because a block was lost unnoticed.
	implausible := false
	// created marks a client block on a stream not yet tracked; sawPseudo
	// that it carried pseudo-headers.
	created, sawPseudo := false, false
	var req *Http2Request
	var emit func(name, value string)
	switch method {
	case MethodHttp2ClientFrames:
		req = p.activeRequests[streamId]
		if req == nil {
			// Added to activeRequests once decoded, if it is a request: see
			// below.
			req = &Http2Request{
				kernelTime: kernelTime,
			}
			created = true
		}
		emit = func(name, value string) {
			if strings.HasPrefix(name, ":") {
				sawPseudo = true
			}
			switch name {
			case ":method":
				if !isHttpMethod(value) {
					implausible = true
				} else if req != nil && req.Method == "" {
					req.Method = value
				}
			case ":path":
				if !isHttpPath(value) {
					implausible = true
				} else if req != nil && req.Path == "" {
					req.Path = value
				}
			case ":scheme":
				if req != nil && req.Scheme == "" && isHttpScheme(value) {
					req.Scheme = value
				}
			case ":authority":
				if req != nil && req.Authority == "" && value != "" {
					req.Authority = value
				}
			case "content-type":
				if req != nil && req.ContentType == "" && value != "" {
					req.ContentType = value
				}
			case ":status":
				implausible = true
			}
		}

	case MethodHttp2ServerFrames:
		req := p.activeRequests[streamId]
		if req == nil {
			// Request not found - this can happen if request came on a different connection
			if _, ok := statuses[streamId]; !ok {
				statuses[streamId] = 0
			}
		}
		emit = func(name, value string) {
			switch name {
			case ":status":
				s, err := strconv.Atoi(value)
				if err != nil || s < 100 || s > 999 {
					implausible = true
					return
				}
				if req != nil {
					req.Status = Status(s)
					if !req.hasResponseStatus {
						p.stage("response_status")
					}
					req.hasResponseStatus = true
				}
				statuses[streamId] = Status(s)
			case "grpc-status":
				s, _ := strconv.Atoi(value)
				if req != nil {
					req.GrpcStatus = Status(s)
				}
				grpcStatuses[streamId] = Status(s)
			case ":method", ":path", ":scheme", ":authority":
				implausible = true
			}
		}
		// Check for END_STREAM flag on HEADERS (no body response)
		if req != nil && endStream {
			if !req.responseEndStream {
				p.stage("end_stream")
			}
			req.responseEndStream = true
		}
	default:
		return
	}

	// Fields are emitted as they decode, so on an error the ones before it
	// (often :method or :status, from the static table) are kept.
	unknown, err := decoder.decode(hpackData, emit)
	if created {
		// A block with no pseudo-headers on a stream the parser does not
		// track is trailers of a stream it evicted or never saw, not a
		// request. Anything else (including a block it could not fully
		// decode) starts one.
		if sawPseudo || unknown > 0 || err != nil {
			if len(p.activeRequests) >= maxActiveRequests {
				p.evictOldestRequest()
			}
			p.activeRequests[streamId] = req
			p.stage("stream_created")
		}
	}
	if err != nil || unknown > 0 || implausible {
		// Mark the request as having partial headers so downstream can apply fallbacks
		if req := p.activeRequests[streamId]; req != nil {
			req.PartialHeaders = true
		}
	}
	switch {
	case err != nil || implausible:
		klog.V(3).Infof("http2: HPACK decode error on stream %d: %v, implausible=%v (partial headers preserved)", streamId, err, implausible)
		if OnHPACKDecodeError != nil {
			OnHPACKDecodeError()
		}
		p.stage("hpack_error")
		// The block is not valid HPACK, or decoded to headers it cannot
		// contain: either way the table no longer matches the encoder's.
		p.resetDecoder(method)
	case unknown > 0:
		// References to entries inserted before the decoder joined, or before
		// it was reset. Expected, and not an error: the decoder catches up as
		// the encoder inserts new entries.
		p.stage("hpack_partial")
	}
}

// Parse consumes one L7 event's worth of HTTP/2 frames.
//
// missing is the number of bytes of the original read or write that the
// kernel did not capture: eBPF clamps each event to MAX_PAYLOAD_SIZE and drops
// the tail, so the caller passes PayloadSize - len(payload). A partial frame at
// the end of a truncated payload is unrecoverable and must not be carried into
// the next call — see the save site at the end of this function — but when the
// missing bytes all belong to that frame, its remainder at the start of the
// next read is known exactly and is skipped, so framing survives the cut.
// That is the common case for a read or write longer than MAX_PAYLOAD_SIZE.
func (p *Http2Parser) Parse(method Method, payload []byte, kernelTime uint64, missing uint64) []Http2Request {
	truncated := missing > 0
	if method == MethodHttp2ClientFrames {
		l := len(http2.ClientPreface)
		if len(payload) >= l && string(payload[:l]) == http2.ClientPreface {
			payload = payload[l:]
		}
	}
	p.sawValidFrame = false
	if len(payload) == 0 {
		return nil
	}

	var decoder *hpackDecoder
	clear(p.statuses)
	clear(p.grpcStatuses)
	statuses := p.statuses
	grpcStatuses := p.grpcStatuses

	// Prepend any saved partial frame data from previous Parse() call
	// This handles HTTP/2 frames split across multiple S2A/TLS Read() calls
	var partialFrame *[]byte
	var pendingHeaders **pendingHeaderBlock
	var skip *uint64
	switch method {
	case MethodHttp2ClientFrames:
		decoder = p.clientDecoder
		partialFrame = &p.clientPartialFrame
		pendingHeaders = &p.clientPendingHeaders
		skip = &p.clientSkip
	case MethodHttp2ServerFrames:
		decoder = p.serverDecoder
		partialFrame = &p.serverPartialFrame
		pendingHeaders = &p.serverPendingHeaders
		skip = &p.serverSkip
	default:
		return nil
	}

	if *skip > 0 {
		readLen := uint64(len(payload)) + missing
		switch {
		case *skip >= readLen:
			// The whole read is the inside of a frame cut short earlier.
			*skip -= readLen
			p.sawValidFrame = true
			return nil
		case *skip <= uint64(len(payload)):
			payload = payload[*skip:]
			*skip = 0
		default:
			// The frame ends inside this read's own missing tail: whatever
			// follows it was never captured, so framing is lost, and a header
			// block among it took its insertions with it.
			*skip = 0
			p.resetDecoder(method)
			return nil
		}
	}

	if len(*partialFrame) > 0 {
		// Sanity check: if partial frame buffer is too large (>64KB), it's likely corrupted
		// HTTP/2 default max frame size is 16KB, so 64KB should be plenty for reassembly
		if len(*partialFrame) > 64*1024 {
			*partialFrame = nil
			p.resetDecoder(method)
		} else {
			// Prepend saved partial data to new payload
			payload = append(*partialFrame, payload...)
			*partialFrame = nil // Clear the buffer
		}
	}

	offset := 0
	// Note: Do NOT call decoder.Close() here - the HPACK decoders are persistent
	// and maintain dynamic table state across Parse() calls for the connection lifetime

frameLoop:
	for {
		// Save frame start position for partial frame recovery
		frameStart := offset

		if len(payload)-offset < http2FrameHeaderLength {
			break
		}
		h := Http2FrameHeader{
			Length:   int(binary.BigEndian.Uint32(payload[offset:]) >> 8),
			Type:     http2.FrameType(payload[offset+3]),
			Flags:    http2.Flags(payload[offset+4]),
			StreamId: binary.BigEndian.Uint32(payload[offset+5:]) & (1<<31 - 1),
		}

		// Sanity check: HTTP/2 max frame size is 16MB (2^24-1), and frame types are 0-9
		// If we see clearly invalid values, this isn't valid HTTP/2 - skip remaining data
		if h.Length > 16*1024*1024 {
			// Length beyond the 16MB maximum: this is not a frame header.
			// Consume the rest: leaving offset at frameStart would let the
			// partial-frame save at the end of this function buffer the garbage
			// and prepend it to every subsequent call, re-parsing it forever.
			p.frame("invalid")
			offset = len(payload)
			break
		}
		// RFC 9113 4.1: an unknown frame type MUST be ignored and discarded,
		// not treated as an error. ALTSVC (0x0a), ORIGIN (0x0c) and
		// PRIORITY_UPDATE (0x10) are standard extensions that GitHub and Google
		// both send. Breaking here would drop the rest of the payload, and
		// because callers reclassify connections that yield no valid frame, a
		// connection whose payload merely leads with an extension frame could be
		// dropped as if it were misdetected. Skip it and keep parsing.
		// Registered types run to 0x10 (PRIORITY_UPDATE). Anything beyond that
		// is not a plausible extension, and treating it as one would let
		// misdetected binary traffic masquerade as valid HTTP/2 forever.
		if h.Type > 9 && h.Type <= 0x10 {
			p.frame("extension")
			p.sawValidFrame = true
			// offset still points at the frame header here; skip header+payload.
			if len(payload)-offset < http2FrameHeaderLength+h.Length {
				offset = frameStart
				break frameLoop
			}
			offset += http2FrameHeaderLength + h.Length
			continue
		}
		if h.Type > 0x10 {
			// No registered frame type above 0x10; consume the rest for the
			// same reason as the oversized-length case above.
			p.frame("invalid")
			offset = len(payload)
			break
		}
		p.frame(http2FrameTypeName(h.Type))
		p.sawValidFrame = true

		offset += http2FrameHeaderLength

		switch h.Type {
		case http2.FrameData:
			// Extract DATA frame payload
			if len(payload)-offset < h.Length {
				offset = frameStart
				break frameLoop
			}

			// Track END_STREAM on server DATA frames unconditionally (needed for both modes)
			if method == MethodHttp2ServerFrames && h.Flags&http2FlagEndStream != 0 {
				if req := p.activeRequests[h.StreamId]; req != nil {
					if !req.responseEndStream {
						p.stage("end_stream")
					}
					req.responseEndStream = true
				}
			}

			offset += h.Length

		case http2.FrameHeaders:
			// HEADERS frame - must have complete frame data before processing
			if len(payload)-offset < h.Length {
				offset = frameStart
				break frameLoop
			}
			framePayload := payload[offset : offset+h.Length]
			offset += h.Length

			// A header block still waiting for CONTINUATION frames lost them:
			// a new block cannot start before it ends.
			p.dropPendingHeaders(method, pendingHeaders)

			// Extract HPACK data, stripping optional PADDED/PRIORITY fields
			hpackFragment := extractHeaderBlockFragment(h.Flags, framePayload)
			if hpackFragment == nil {
				// Malformed HEADERS frame: its block, and its insertions, are
				// lost.
				p.resetDecoder(method)
				continue
			}

			hasEndHeaders := h.Flags&http2FlagEndHeaders != 0
			endStream := h.Flags&http2FlagEndStream != 0

			if hasEndHeaders {
				// Complete header block in a single HEADERS frame (common case)
				p.decodeHeaderBlock(method, h.StreamId, endStream, hpackFragment,
					decoder, statuses, grpcStatuses, kernelTime)
			} else {
				// HEADERS without END_HEADERS -- start accumulating fragments
				// CONTINUATION frames will follow with the rest of the header block
				fragment := make([]byte, len(hpackFragment))
				copy(fragment, hpackFragment)
				*pendingHeaders = &pendingHeaderBlock{
					streamId:  h.StreamId,
					fragments: fragment,
					endStream: endStream,
				}
			}

		case http2.FrameContinuation:
			// CONTINUATION frame - carries additional HPACK data for a header block
			// Must follow a HEADERS or CONTINUATION frame on the same stream
			if len(payload)-offset < h.Length {
				offset = frameStart
				break frameLoop
			}
			continuationPayload := payload[offset : offset+h.Length]
			offset += h.Length

			// Validate: CONTINUATION must follow a HEADERS on the same stream
			if *pendingHeaders == nil || (*pendingHeaders).streamId != h.StreamId {
				// We missed the HEADERS frame (or this is a protocol error):
				// the block it starts is lost.
				p.dropPendingHeaders(method, pendingHeaders)
				p.resetDecoder(method)
				continue
			}

			// Accumulate fragment (with size limit to prevent unbounded growth)
			pending := *pendingHeaders
			if len(pending.fragments)+len(continuationPayload) > maxPendingHeaderBlockSize {
				// Too large, discard the pending header block
				p.dropPendingHeaders(method, pendingHeaders)
				continue
			}
			pending.fragments = append(pending.fragments, continuationPayload...)

			hasEndHeaders := h.Flags&http2FlagEndHeaders != 0

			if hasEndHeaders {
				// Complete header block -- decode accumulated fragments
				*pendingHeaders = nil
				p.decodeHeaderBlock(method, pending.streamId, pending.endStream,
					pending.fragments, decoder, statuses, grpcStatuses, kernelTime)
			}

		default:
			// Other frame types (SETTINGS, WINDOW_UPDATE, PING, etc.) - skip
			if len(payload)-offset < h.Length {
				offset = frameStart
				break frameLoop
			}
			offset += h.Length
		}
	}

	// Save any unconsumed data as partial frame for next Parse() call.
	// This handles HTTP/2 frames split across multiple TLS Read()/Write() calls.
	//
	// Never do this for a truncated payload. eBPF caps each event at
	// MAX_PAYLOAD_SIZE (4096) and DISCARDS the remainder rather than chunking it,
	// so the bytes that would complete this frame do not exist and never will.
	// Buffering the fragment splices it onto the front of the next, unrelated
	// write: every frame header after that point is read at the wrong offset, and
	// the resulting garbage is fed to the persistent HPACK decoder. Because HPACK
	// is stateful, that corrupts the dynamic table for the remaining life of the
	// connection — one oversized write silently kills decoding for all subsequent
	// requests on it. Dropping the fragment loses that one frame instead.
	//
	// This is why large-header HTTPS/2 endpoints decode nothing while small
	// internal h2c (frames well under 4KB) works: only the former truncates.
	if truncated {
		// The table survives only if the missing bytes are known to be the
		// tail of one frame that is not part of a header block. Otherwise a
		// header block may be among them: the cut frame itself, or a frame
		// after it (one write often holds a response's DATA and then its
		// trailers), or one whose header was never captured. Its insertions
		// are missing from the table, which would decode later references to
		// the wrong headers.
		lostHeaders := true
		if rest := len(payload) - offset; rest >= http2FrameHeaderLength {
			length := uint64(binary.BigEndian.Uint32(payload[offset:]) >> 8)
			captured := uint64(rest - http2FrameHeaderLength)
			// If the missing tail lies entirely within the cut frame, the rest
			// of that frame opens the next read: skip exactly that much there.
			if length >= captured+missing {
				*skip = length - captured - missing
				t := http2.FrameType(payload[offset+3])
				lostHeaders = t == http2.FrameHeaders || t == http2.FrameContinuation
			}
		}
		if lostHeaders {
			p.resetDecoder(method)
		}
		*partialFrame = nil
		// A header block interrupted by truncation can never be completed by a
		// CONTINUATION frame, and feeding its fragments to the decoder later
		// would desync the dynamic table just as badly.
		p.dropPendingHeaders(method, pendingHeaders)
	} else if offset < len(payload) {
		remaining := payload[offset:]
		// Only save if it looks like start of a valid frame (has at least some bytes)
		// and isn't too large (sanity check - max HTTP/2 frame is 16MB)
		if len(remaining) > 0 && len(remaining) < 16*1024*1024 {
			*partialFrame = make([]byte, len(remaining))
			copy(*partialFrame, remaining)
		}
	}

	var res []Http2Request

	// Return only requests that have BOTH response status AND END_STREAM
	// This ensures we capture complete streaming responses (like LLM API calls)
	for streamId, r := range p.activeRequests {
		if r == nil {
			continue
		}

		// Check if request is complete: has response status AND end of stream
		if r.hasResponseStatus && r.responseEndStream {
			// Set grpc status if not already set
			if r.GrpcStatus == 0 {
				if grpcStatus, ok := grpcStatuses[streamId]; ok {
					r.GrpcStatus = grpcStatus
				} else {
					r.GrpcStatus = -1
				}
			}
			r.Duration = safeKernelDuration(kernelTime, r.kernelTime)
			res = append(res, *r)
			p.stage("completed")
			delete(p.activeRequests, streamId)
		}
	}

	// Also check statuses map for backward compatibility (orphan statuses without tracked request)
	for streamId, status := range statuses {
		r := p.activeRequests[streamId]
		if r == nil {
			continue
		}
		// If we have status but request wasn't returned above, it might be
		// a non-streaming response where END_STREAM was on HEADERS
		if r.hasResponseStatus && r.responseEndStream {
			// Already processed above
			continue
		}
		// For requests where we got status but haven't tracked END_STREAM properly,
		// still return them (backward compatibility)
		if r.hasResponseStatus && !r.responseEndStream {
			// Give streaming responses some time to complete
			// Only return if request has been waiting for a while
			continue
		}
		// Fallback: if status came from decoder but request state wasn't updated
		if !r.hasResponseStatus && status > 0 {
			r.Status = status
			grpcStatus, ok := grpcStatuses[streamId]
			if ok {
				r.GrpcStatus = grpcStatus
			} else {
				r.GrpcStatus = -1
			}
			r.Duration = safeKernelDuration(kernelTime, r.kernelTime)
			res = append(res, *r)
			delete(p.activeRequests, streamId)
		}
	}

	// GC
	if kernelTime-p.lastGcTime > http2DecoderGcInterval {
		if p.lastGcTime > 0 {
			for streamId, r := range p.activeRequests {
				if kernelTime-r.kernelTime > http2DecoderGcInterval {
					delete(p.activeRequests, streamId)
				}
			}
			// Clear stale pending headers
			p.dropPendingHeaders(MethodHttp2ClientFrames, &p.clientPendingHeaders)
			p.dropPendingHeaders(MethodHttp2ServerFrames, &p.serverPendingHeaders)
		}
		p.lastGcTime = kernelTime
	}

	return res
}

func isHttpMethod(s string) bool {
	switch s {
	case http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace:
		return true
	}
	return false
}

func isHttpPath(s string) bool {
	return strings.HasPrefix(s, "/") || s == "*"
}

func isHttpScheme(s string) bool {
	return s == "http" || s == "https"
}
