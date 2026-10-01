package llm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// maxDecodedBody caps a decompressed response. LLM responses are text; a
// body past this is not one, and is not worth the memory.
const maxDecodedBody = 32 << 20

var errUnsupportedEncoding = errors.New("unsupported content-encoding")

// decodeBody undoes Content-Encoding. Clients add Accept-Encoding on their
// own (Go's net/http asks for gzip by default), so compressed LLM responses
// are the norm rather than the exception.
func decodeBody(encoding string, body []byte) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r = zr
	case "deflate":
		// RFC 9110 deflate is zlib-wrapped, but raw deflate is common enough.
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(body))
		}
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return nil, errUnsupportedEncoding
	}
	return io.ReadAll(io.LimitReader(r, maxDecodedBody))
}

// payloads splits a decoded response body into the JSON documents that carry
// its content: one for a plain response, one per event for a stream.
func payloads(contentType string, body []byte) [][]byte {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "text/event-stream"):
		return sseData(body)
	case strings.Contains(ct, "application/vnd.amazon.eventstream"):
		return eventStreamPayloads(body)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		// Gemini's streamGenerateContent without alt=sse streams a JSON array.
		return jsonArrayElements(trimmed)
	}
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		// Some servers stream SSE under a JSON or missing content type.
		return sseData(body)
	}
	return [][]byte{trimmed}
}

// sseData returns the data of each server-sent event, joining multi-line
// data fields as the SSE spec requires and skipping OpenAI's [DONE] sentinel.
func sseData(body []byte) [][]byte {
	var events [][]byte
	var cur []byte
	flush := func() {
		if len(cur) > 0 && !bytes.Equal(cur, []byte("[DONE]")) {
			events = append(events, cur)
		}
		cur = nil
	}
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			flush()
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		v := bytes.TrimPrefix(line[len("data:"):], []byte(" "))
		if cur != nil {
			cur = append(cur, '\n')
		}
		cur = append(cur, v...)
	}
	flush()
	return events
}

func jsonArrayElements(body []byte) [][]byte {
	var out [][]byte
	depth, start := 0, -1
	inString, escaped := false, false
	for i, c := range body {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, body[start:i+1])
				start = -1
			}
		}
	}
	return out
}

// eventStreamPayloads decodes AWS event-stream framing, used by Bedrock's
// streaming APIs. Each message is: total length, headers length, prelude CRC,
// headers, payload, message CRC. CRCs are not checked; the capture is not a
// network hop that can corrupt bytes.
func eventStreamPayloads(body []byte) [][]byte {
	var out [][]byte
	for len(body) >= 16 {
		total := int(binary.BigEndian.Uint32(body[0:4]))
		headers := int(binary.BigEndian.Uint32(body[4:8]))
		if total < 16 || total > len(body) || 12+headers > total-4 {
			break
		}
		if eventStreamType(body[12:12+headers]) == "event" {
			out = append(out, body[12+headers:total-4])
		}
		body = body[total:]
	}
	return out
}

// eventStreamType returns the :message-type header ("event" or "exception").
func eventStreamType(h []byte) string {
	for len(h) > 0 {
		n := int(h[0])
		if 1+n+1 > len(h) {
			return ""
		}
		name, typ := string(h[1:1+n]), h[1+n]
		h = h[2+n:]
		var size int
		switch typ {
		case 0, 1: // bool true/false
			size = 0
		case 2: // byte
			size = 1
		case 3: // short
			size = 2
		case 4: // int
			size = 4
		case 5, 8: // long, timestamp
			size = 8
		case 9: // uuid
			size = 16
		case 6, 7: // bytes, string
			if len(h) < 2 {
				return ""
			}
			size = 2 + int(binary.BigEndian.Uint16(h[0:2]))
		default:
			return ""
		}
		if size > len(h) {
			return ""
		}
		if name == ":message-type" && typ == 7 {
			return string(h[2:size])
		}
		h = h[size:]
	}
	return ""
}
