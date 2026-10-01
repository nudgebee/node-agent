package l7

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// frame builds a single HTTP/2 frame.
func frame(t http2.FrameType, flags http2.Flags, streamID uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0] = byte(len(payload) >> 16)
	b[1] = byte(len(payload) >> 8)
	b[2] = byte(len(payload))
	b[3] = byte(t)
	b[4] = byte(flags)
	binary.BigEndian.PutUint32(b[5:], streamID)
	copy(b[9:], payload)
	return b
}

// headersFrame builds a complete HEADERS frame for a request.
func headersFrame(streamID uint32, path string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.github.com"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	return frame(http2.FrameHeaders, http2FlagEndHeaders, streamID, buf.Bytes())
}

// A write larger than the eBPF capture limit arrives truncated: the tail is
// discarded, not delivered later. Carrying the trailing fragment into the next
// Parse call splices it onto an unrelated write, misaligning every subsequent
// frame header and corrupting the persistent HPACK decoder for the rest of the
// connection. This is what made large-header HTTPS/2 endpoints decode nothing
// while small internal h2c worked.
func TestHttp2TruncatedPayloadDoesNotCorruptFollowingParses(t *testing.T) {
	p := NewHttp2Parser()

	// Write 1: a valid HEADERS frame, then a second frame the kernel cut short.
	complete := headersFrame(1, "/repos/nudgebee/node-agent")
	cutShort := frame(http2.FrameData, 0, 1, make([]byte, 4000))
	cutShort = cutShort[:len(cutShort)-3000] // kernel captured only a prefix

	full := append(append([]byte{}, complete...), cutShort...)
	p.Parse(MethodHttp2ClientFrames, full, 1, 1<<20 /* truncated */)

	// Write 2: an unrelated, complete HEADERS frame. It must still decode.
	next := headersFrame(3, "/user/repos")
	p.Parse(MethodHttp2ClientFrames, next, 2, 0)

	req := p.activeRequests[3]
	if req == nil {
		t.Fatal("stream 3 was lost: truncated fragment corrupted the next parse")
	}
	if req.Path != "/user/repos" {
		t.Errorf("path = %q, want /user/repos", req.Path)
	}
	if req.Authority != "api.github.com" {
		t.Errorf("authority = %q, want api.github.com", req.Authority)
	}
}

// The fragment must be dropped, not buffered, when the payload was truncated —
// the bytes that would complete it were discarded in the kernel and never arrive.
func TestHttp2TruncatedPayloadDropsPartialFrame(t *testing.T) {
	p := NewHttp2Parser()

	cutShort := frame(http2.FrameData, 0, 1, make([]byte, 4000))
	cutShort = cutShort[:len(cutShort)-3000]
	p.Parse(MethodHttp2ClientFrames, cutShort, 1, 1<<20)

	if len(p.clientPartialFrame) != 0 {
		t.Errorf("buffered %d bytes of an unrecoverable frame; want 0", len(p.clientPartialFrame))
	}
	if p.clientPendingHeaders != nil {
		t.Error("pending header block survived truncation; it can never be completed")
	}
}

// Genuine cross-read splits — where the remainder really does arrive next time —
// must still reassemble. Only truncation drops the fragment.
func TestHttp2NonTruncatedSplitStillReassembles(t *testing.T) {
	p := NewHttp2Parser()

	h := headersFrame(1, "/split/path")
	split := len(h) - 5

	p.Parse(MethodHttp2ClientFrames, h[:split], 1, 0 /* not truncated */)
	if len(p.clientPartialFrame) == 0 {
		t.Fatal("split frame was not buffered for reassembly")
	}
	p.Parse(MethodHttp2ClientFrames, h[split:], 2, 0)

	req := p.activeRequests[1]
	if req == nil {
		t.Fatal("stream 1 missing: reassembly across reads regressed")
	}
	if req.Path != "/split/path" {
		t.Errorf("path = %q, want /split/path", req.Path)
	}
}

// Go reads 4096 bytes at a time and the kernel keeps 4095. The frame that
// straddles the cut must not take the frames after it down with it: the rest
// of it opens the next read, and is skipped exactly.
func TestHttp2ResyncAfterOneByteCut(t *testing.T) {
	enc := func(path string, streamID uint32) []byte {
		var hb bytes.Buffer
		e := hpack.NewEncoder(&hb)
		for _, f := range []hpack.HeaderField{{Name: ":method", Value: "POST"}, {Name: ":path", Value: path}, {Name: ":authority", Value: "example.com"}, {Name: ":scheme", Value: "https"}} {
			_ = e.WriteField(f)
		}
		var fb bytes.Buffer
		fr := http2.NewFramer(&fb, nil)
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb.Bytes(), EndHeaders: true})
		return fb.Bytes()
	}
	var stream bytes.Buffer
	stream.Write(enc("/one", 1))
	fr := http2.NewFramer(&stream, nil)
	_ = fr.WriteData(1, false, bytes.Repeat([]byte("x"), 6000)) // straddles the 4096 boundary
	stream.Write(enc("/two", 3))

	all := stream.Bytes()
	p := NewHttp2Parser()
	// First read: 4096 bytes of which 4095 were captured.
	p.Parse(MethodHttp2ClientFrames, all[:4095], 1, 1)
	// Second read: the rest of the DATA frame, then the next HEADERS.
	p.Parse(MethodHttp2ClientFrames, all[4096:], 2, 0)
	got := map[string]bool{}
	for _, r := range p.activeRequests {
		got[r.Path] = true
	}
	if !got["/one"] || !got["/two"] {
		t.Fatalf("paths parsed: %v, want /one and /two", got)
	}
}
