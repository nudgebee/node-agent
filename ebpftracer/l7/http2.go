package l7

import (
	"encoding/binary"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"k8s.io/klog/v2"
)

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

	RequestPayload  []byte
	ResponsePayload []byte
	kernelTime      uint64

	// Headers for trace correlation
	RequestHeaders map[string]string // All request headers including traceparent

	// Internal state for tracking stream completion
	hasResponseStatus bool // true when we've received :status in response HEADERS
	responseEndStream bool // true when we've received END_STREAM on response

	// Timing for TTFT calculation
	firstResponseTime uint64 // Kernel time when first response data received

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
	clientDecoder  *hpack.Decoder
	serverDecoder  *hpack.Decoder
	activeRequests map[uint32]*Http2Request
	lastGcTime     uint64

	// Buffers for partial frame reassembly across Read() calls
	// Needed because S2A/TLS returns small chunks that may split HTTP/2 frames
	clientPartialFrame []byte
	serverPartialFrame []byte

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
		clientDecoder:  hpack.NewDecoder(4096, nil),
		serverDecoder:  hpack.NewDecoder(4096, nil),
		activeRequests: map[uint32]*Http2Request{},
	}
}

// resetDecoder creates a fresh HPACK decoder after an unrecoverable decode error.
// This discards the dynamic table but preserves static table (indices 1-61) functionality.
// Headers like :method (2,3), :path (4,5), :scheme (6,7), :status (8-14) remain decodable.
// The dynamic table gradually rebuilds as the encoder sends new literal-with-indexing headers.
func (p *Http2Parser) resetDecoder(method Method) {
	switch method {
	case MethodHttp2ClientFrames:
		p.clientDecoder = hpack.NewDecoder(4096, nil)
		p.clientDecoderDegraded = true
	case MethodHttp2ServerFrames:
		p.serverDecoder = hpack.NewDecoder(4096, nil)
		p.serverDecoderDegraded = true
	}
}

// ActiveRequestCount returns the number of HTTP/2 requests currently being tracked
// (waiting for response completion)
func (p *Http2Parser) ActiveRequestCount() int {
	return len(p.activeRequests)
}

// Http2StreamUpdate contains information about an active HTTP/2 stream
// Used for notifying LLM stream tracker about streaming responses
type Http2StreamUpdate struct {
	StreamId          uint32
	Path              string
	Method            string
	Authority         string
	Scheme            string
	Status            Status
	RequestHeaders    map[string]string
	ResponsePayload   []byte
	HasResponseStatus bool
	KernelTime        uint64
	FirstResponseTime uint64
}

// GetActiveStreamsForLLM returns info about active streams that may be LLM requests
// This allows the LLM stream tracker to detect SSE completion markers
func (p *Http2Parser) GetActiveStreamsForLLM() []Http2StreamUpdate {
	var updates []Http2StreamUpdate
	for streamId, req := range p.activeRequests {
		if req == nil {
			continue
		}
		// Only return streams that have received response status (response started)
		// and have response payload (data to analyze for SSE markers)
		if req.hasResponseStatus && len(req.ResponsePayload) > 0 {
			updates = append(updates, Http2StreamUpdate{
				StreamId:          streamId,
				Path:              req.Path,
				Method:            req.Method,
				Authority:         req.Authority,
				Scheme:            req.Scheme,
				Status:            req.Status,
				RequestHeaders:    req.RequestHeaders,
				ResponsePayload:   req.ResponsePayload,
				HasResponseStatus: req.hasResponseStatus,
				KernelTime:        req.kernelTime,
				FirstResponseTime: req.firstResponseTime,
			})
		}
	}
	return updates
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
// It sets up the emit function, writes the HPACK data to the decoder, and handles errors.
func (p *Http2Parser) decodeHeaderBlock(
	method Method,
	streamId uint32,
	endStream bool,
	hpackData []byte,
	decoder *hpack.Decoder,
	statuses map[uint32]Status,
	grpcStatuses map[uint32]Status,
	kernelTime uint64,
) {
	switch method {
	case MethodHttp2ClientFrames:
		req := p.activeRequests[streamId]
		if req == nil {
			req = &Http2Request{
				kernelTime:     kernelTime,
				RequestHeaders: make(map[string]string),
			}
			p.activeRequests[streamId] = req
		}
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
			// Store all headers for trace correlation
			if req.RequestHeaders != nil {
				req.RequestHeaders[hf.Name] = hf.Value
			}

			switch hf.Name {
			case ":method":
				if req.Method == "" && isHttpMethod(hf.Value) {
					req.Method = hf.Value
				}
			case ":path":
				if req.Path == "" && isHttpPath(hf.Value) {
					req.Path = hf.Value
				}
			case ":scheme":
				if req.Scheme == "" && isHttpScheme(hf.Value) {
					req.Scheme = hf.Value
				}
			case ":authority":
				if req.Authority == "" && hf.Value != "" {
					req.Authority = hf.Value
				}
			case "content-type":
				if req.ContentType == "" && hf.Value != "" {
					req.ContentType = hf.Value
				}
			}
		})

	case MethodHttp2ServerFrames:
		req := p.activeRequests[streamId]
		if req == nil {
			// Request not found - this can happen if request came on a different connection
			if _, ok := statuses[streamId]; !ok {
				statuses[streamId] = 0
			}
		}
		decoder.SetEmitFunc(func(hf hpack.HeaderField) {
			switch hf.Name {
			case ":status":
				s, _ := strconv.Atoi(hf.Value)
				if req != nil {
					req.Status = Status(s)
					req.hasResponseStatus = true
				}
				statuses[streamId] = Status(s)
			case "grpc-status":
				s, _ := strconv.Atoi(hf.Value)
				if req != nil {
					req.GrpcStatus = Status(s)
				}
				grpcStatuses[streamId] = Status(s)
			}
		})
		// Check for END_STREAM flag on HEADERS (no body response)
		if req != nil && endStream {
			req.responseEndStream = true
		}
	}

	// Decode the complete HPACK header block.
	// The emit function (set above) fires per-header, so headers decoded before any
	// error are already stored in the request struct (e.g., :method from static index 3,
	// :status from static index 8). We preserve these partial results on error.
	if _, err := decoder.Write(hpackData); err != nil {
		// HPACK decode error - commonly happens during mid-stream join when the agent
		// starts monitoring after HTTP/2 connection was established. The remote encoder's
		// dynamic table has entries our decoder doesn't have.
		klog.V(3).Infof("http2: HPACK decode error on stream %d: %v (partial headers preserved)", streamId, err)

		// Mark the request as having partial headers so downstream can apply fallbacks
		if req := p.activeRequests[streamId]; req != nil {
			req.PartialHeaders = true
		}

		// Reset the decoder to prevent cascading failures. After a decode error, the
		// decoder's internal buffer position and dynamic table are desynchronized.
		// A fresh decoder starts with an empty dynamic table but static table (indices 1-61)
		// always works. The dynamic table rebuilds from new literal-with-indexing headers.
		p.resetDecoder(method)
	}
}

func (p *Http2Parser) Parse(method Method, payload []byte, kernelTime uint64) []Http2Request {
	if method == MethodHttp2ClientFrames {
		l := len(http2.ClientPreface)
		if len(payload) >= l && string(payload[:l]) == http2.ClientPreface {
			payload = payload[l:]
		}
	}
	if len(payload) == 0 {
		return nil
	}

	var decoder *hpack.Decoder
	statuses := map[uint32]Status{}
	grpcStatuses := map[uint32]Status{}

	// Prepend any saved partial frame data from previous Parse() call
	// This handles HTTP/2 frames split across multiple S2A/TLS Read() calls
	var partialFrame *[]byte
	var pendingHeaders **pendingHeaderBlock
	switch method {
	case MethodHttp2ClientFrames:
		decoder = p.clientDecoder
		partialFrame = &p.clientPartialFrame
		pendingHeaders = &p.clientPendingHeaders
	case MethodHttp2ServerFrames:
		decoder = p.serverDecoder
		partialFrame = &p.serverPartialFrame
		pendingHeaders = &p.serverPendingHeaders
	default:
		return nil
	}

	if len(*partialFrame) > 0 {
		// Sanity check: if partial frame buffer is too large (>64KB), it's likely corrupted
		// HTTP/2 default max frame size is 16KB, so 64KB should be plenty for reassembly
		if len(*partialFrame) > 64*1024 {
			*partialFrame = nil
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
		if h.Length > 16*1024*1024 || h.Type > 9 {
			// Invalid frame - don't save as partial, just discard
			break
		}

		offset += http2FrameHeaderLength

		switch h.Type {
		case http2.FrameData:
			// Extract DATA frame payload
			if len(payload)-offset < h.Length {
				offset = frameStart
				break frameLoop
			}
			dataPayload := payload[offset : offset+h.Length]

			switch method {
			case MethodHttp2ClientFrames:
				// Client DATA frame = request payload
				req := p.activeRequests[h.StreamId]
				if req != nil {
					req.RequestPayload = append(req.RequestPayload, dataPayload...)
				}
			case MethodHttp2ServerFrames:
				// Server DATA frame = response payload
				req := p.activeRequests[h.StreamId]
				if req != nil {
					// Track first response time for TTFT
					if req.firstResponseTime == 0 && len(dataPayload) > 0 {
						req.firstResponseTime = kernelTime
					}
					req.ResponsePayload = append(req.ResponsePayload, dataPayload...)
					// Check for END_STREAM flag on DATA frame
					if h.Flags&http2FlagEndStream != 0 {
						req.responseEndStream = true
					}
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

			// Extract HPACK data, stripping optional PADDED/PRIORITY fields
			hpackFragment := extractHeaderBlockFragment(h.Flags, framePayload)
			if hpackFragment == nil {
				// Malformed HEADERS frame, skip
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
				// Protocol error or we missed the HEADERS frame -- discard
				*pendingHeaders = nil
				continue
			}

			// Accumulate fragment (with size limit to prevent unbounded growth)
			pending := *pendingHeaders
			if len(pending.fragments)+len(continuationPayload) > maxPendingHeaderBlockSize {
				// Too large, discard the pending header block
				*pendingHeaders = nil
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

	// Save any unconsumed data as partial frame for next Parse() call
	// This handles HTTP/2 frames split across multiple S2A/TLS Read() calls
	if offset < len(payload) {
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
			p.clientPendingHeaders = nil
			p.serverPendingHeaders = nil
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
