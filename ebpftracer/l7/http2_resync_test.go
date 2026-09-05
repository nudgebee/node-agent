package l7

import (
	"testing"

	"golang.org/x/net/http2"
)

// After a truncated event, the next event does NOT begin on a frame boundary:
// eBPF discarded the tail of the previous write, so the bytes that would have
// finished that frame are gone. Parse() assumes every payload starts at a frame
// header, so from that point on it reads frame headers at the wrong offset.
//
// HTTP/2 has no resynchronisation marker, so alignment cannot be recovered by
// scanning. This is the difference between losing one frame and losing the
// connection, and it is what #316 did not address: dropping the partial
// fragment stops HPACK from being fed garbage, but the stream is still
// misaligned from the next event onward.
func TestHttp2TruncationLosesFrameAlignment(t *testing.T) {
	p := NewHttp2Parser()
	p.Lightweight = true

	// A write carrying two frames, where the kernel captured only part of it.
	big := frame(http2.FrameData, 0, 1, make([]byte, 3000))
	full := append(append([]byte{}, big...), headersFrame(1, "/first")...)
	captured := full[:2000] // truncated mid-DATA; everything after is discarded

	p.Parse(MethodHttp2ClientFrames, captured, 1, true)

	// The next write starts a new request. In the real stream this begins at a
	// frame boundary, and the parser sees it as such, so it must decode.
	p.Parse(MethodHttp2ClientFrames, headersFrame(3, "/second"), 2, false)

	if p.activeRequests[3] == nil {
		t.Fatal("stream 3 lost: parser did not recover after a truncated event")
	}
	if got := p.activeRequests[3].Path; got != "/second" {
		t.Errorf("path = %q, want /second", got)
	}
}

// The harmful case: truncation lands inside a frame, and the *next* event
// continues that same frame's payload rather than starting a new one. The
// parser has no way to know, so it reads payload bytes as a frame header.
func TestHttp2MidFrameContinuationIsMisread(t *testing.T) {
	p := NewHttp2Parser()
	p.Lightweight = true

	// Frame 1 is a large DATA frame whose payload happens to contain bytes that
	// parse as a plausible frame header — ordinary for compressed/binary bodies.
	payload := make([]byte, 3000)
	payload[0], payload[1], payload[2] = 0x00, 0x00, 0x08 // length 8
	payload[3] = byte(http2.FrameHeaders)                 // type HEADERS
	payload[4] = http2FlagEndHeaders
	payload[8] = 0x63 // stream id 99
	dataFrame := frame(http2.FrameData, 0, 1, payload)

	full := append(append([]byte{}, dataFrame...), headersFrame(1, "/real")...)
	p.Parse(MethodHttp2ClientFrames, full[:1500], 1, true) // truncated mid-DATA

	// Continuation of the SAME frame's payload arrives as the next event.
	p.Parse(MethodHttp2ClientFrames, full[1500:3000], 2, false)

	// Whatever happens, a phantom stream invented from payload bytes would be
	// worse than decoding nothing: it corrupts the request map.
	if _, phantom := p.activeRequests[99]; phantom {
		t.Error("parser invented stream 99 from DATA payload read as a frame header")
	}
}

// A connection the eBPF heuristic mistagged as HTTP/2 yields no structurally
// valid frame. SawValidFrame is what lets the caller notice and reclassify it,
// instead of feeding the HPACK decoder garbage for the connection's lifetime.
func TestHttp2SawValidFrameDistinguishesGarbage(t *testing.T) {
	p := NewHttp2Parser()
	p.Lightweight = true

	// Real frames set it.
	p.Parse(MethodHttp2ClientFrames, headersFrame(1, "/real"), 1, false)
	if !p.SawValidFrame() {
		t.Fatal("valid HEADERS frame not reported as valid")
	}

	// Binary that is not HTTP/2: frame type byte is out of range (>9), which is
	// what the parser rejects. Mirrors an HTTPS/1.1 body misdetected upstream.
	garbage := []byte{0x00, 0x00, 0x10, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef}
	p2 := NewHttp2Parser()
	p2.Lightweight = true
	p2.Parse(MethodHttp2ClientFrames, garbage, 1, false)
	if p2.SawValidFrame() {
		t.Error("non-HTTP/2 binary reported as containing a valid frame")
	}

	// An empty payload must not look like garbage — callers skip those.
	p3 := NewHttp2Parser()
	p3.Lightweight = true
	p3.Parse(MethodHttp2ClientFrames, nil, 1, false)
	if p3.SawValidFrame() {
		t.Error("empty payload reported as containing a valid frame")
	}
}
