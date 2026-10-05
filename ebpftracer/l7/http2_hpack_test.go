package l7

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// countStages records parser stages for the duration of a test.
func countStages(t *testing.T) map[string]int {
	stages := map[string]int{}
	prev := OnHttp2Stage
	OnHttp2Stage = func(stage, dest string) { stages[stage]++ }
	t.Cleanup(func() { OnHttp2Stage = prev })
	return stages
}

func requestPath(i int) string { return fmt.Sprintf("/v1/items/%d", i%7) }

// encodeRequests encodes n request header blocks on one connection.
func encodeRequests(n int) [][]byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	out := make([][]byte, n)
	for i := range out {
		buf.Reset()
		for _, f := range []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "api.example.com"},
			{Name: ":path", Value: requestPath(i)},
			{Name: "user-agent", Value: "client/1.2.3"},
			{Name: "x-request-id", Value: fmt.Sprintf("req-%08d-%08d", i, i*7919)},
		} {
			_ = enc.WriteField(f)
		}
		out[i] = append([]byte(nil), buf.Bytes()...)
	}
	return out
}

func streamID(i int) uint32 { return uint32(2*i + 1) }

// A parser that joins a connection mid-stream used to fail every header block
// for good (see TestHpackDecoderRecoversAfterJoiningMidStream); it now
// decodes method, path and authority again once the peer's table turns over,
// and never counts the references it cannot resolve as errors.
func TestHttp2ParserRecoversAfterJoiningMidStream(t *testing.T) {
	stages := countStages(t)
	const join, n = 20, 300
	blocks := encodeRequests(n)
	p := NewHttp2Parser()
	for i := join; i < n; i++ {
		p.Parse(MethodHttp2ClientFrames, frame(http2.FrameHeaders, http2FlagEndHeaders|http2FlagEndStream, streamID(i), blocks[i]), uint64(i), 0)
		req := p.activeRequests[streamID(i)]
		if req == nil {
			t.Fatalf("request %d: no stream", i)
		}
		if req.Path != "" && req.Path != requestPath(i) {
			t.Fatalf("request %d: path %q, want %q", i, req.Path, requestPath(i))
		}
		if i >= n-50 && (req.Method != "GET" || req.Path != requestPath(i) || req.Authority != "api.example.com") {
			t.Fatalf("request %d not fully decoded: %+v", i, *req)
		}
		delete(p.activeRequests, streamID(i)) // as a response would
	}
	if stages["hpack_error"] != 0 {
		t.Errorf("hpack_error = %d, want 0", stages["hpack_error"])
	}
	if stages["hpack_partial"] == 0 {
		t.Error("no hpack_partial: the join was not exercised")
	}
}

// A HEADERS frame cut short by truncation never reaches the decoder, so the
// entries it inserted are missing and every older index is off by their
// count. Decoding on would resolve later references to the wrong entries;
// the parser resets the table instead, and those references come back as
// unknown, never as wrong values.
func TestHttp2ParserResetsTableWhenAHeaderBlockIsLost(t *testing.T) {
	const lost, n = 10, 200
	blocks := encodeRequests(n)

	// Without the reset, a decoder that misses the block decodes later
	// references to the wrong entries. Check that first, or this test proves
	// nothing.
	d := newHpackDecoder()
	wrong := 0
	for i := 0; i < n; i++ {
		if i == lost {
			continue
		}
		d.decode(blocks[i], func(name, value string) {
			if name == ":path" && value != requestPath(i) {
				wrong++
			}
		})
	}
	if wrong == 0 {
		t.Fatal("losing a block did not misdecode anything; the scenario is too weak")
	}

	stages := countStages(t)
	p := NewHttp2Parser()
	for i := 0; i < n; i++ {
		f := frame(http2.FrameHeaders, http2FlagEndHeaders|http2FlagEndStream, streamID(i), blocks[i])
		if i == lost {
			// The kernel captured only the first bytes of this write.
			p.Parse(MethodHttp2ClientFrames, f[:http2FrameHeaderLength+2], uint64(i), uint64(len(f)-http2FrameHeaderLength-2))
			continue
		}
		p.Parse(MethodHttp2ClientFrames, f, uint64(i), 0)
		req := p.activeRequests[streamID(i)]
		if req == nil {
			t.Fatalf("request %d: no stream", i)
		}
		if req.Path != "" && req.Path != requestPath(i) {
			t.Fatalf("request %d: path %q, want %q", i, req.Path, requestPath(i))
		}
		if req.Authority != "" && req.Authority != "api.example.com" {
			t.Fatalf("request %d: authority %q", i, req.Authority)
		}
		if i >= n-50 && req.Path != requestPath(i) {
			t.Fatalf("request %d: not recovered: %+v", i, *req)
		}
		delete(p.activeRequests, streamID(i))
	}
	if stages["hpack_error"] != 0 {
		t.Errorf("hpack_error = %d, want 0", stages["hpack_error"])
	}
}

// Pseudo-headers that cannot appear in a block's direction mean the table
// has drifted (a block was lost unnoticed): the block counts as an error and
// the table is reset rather than trusted.
func TestHttp2ParserResetsTableOnImplausibleHeaders(t *testing.T) {
	stages := countStages(t)
	p := NewHttp2Parser()
	p.serverDecoder.insert(hpackEntry{HeaderField: hpack.HeaderField{Name: "x-a", Value: "1"}})

	var buf bytes.Buffer
	_ = hpack.NewEncoder(&buf).WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	p.Parse(MethodHttp2ServerFrames, frame(http2.FrameHeaders, http2FlagEndHeaders, 1, buf.Bytes()), 1, 0)

	if stages["hpack_error"] != 1 {
		t.Errorf("hpack_error = %d, want 1", stages["hpack_error"])
	}
	if len(p.serverDecoder.dynamic) != 0 {
		t.Error("server table not reset")
	}
}
