package l7

import (
	"bytes"
	"io"

	"github.com/ClickHouse/ch-go/proto"
)

const clickhouseClientCodeQuery = 1

func ParseClickhouse(payload []byte) (result string) {
	// Recover from panics caused by malformed/incomplete packets
	defer func() {
		if r := recover(); r != nil {
			result = ""
		}
	}()

	// Layer 2: Structural validation before invoking ch-go.
	// Reject misidentified payloads early, before the library can
	// decode garbage varint lengths and attempt unbounded allocations.
	if len(payload) < 3 {
		return ""
	}
	if payload[0] != clickhouseClientCodeQuery {
		return ""
	}
	// Query ID length is varint-encoded. Single-byte varints (0-127) cover
	// all practical query IDs. Multi-byte varints (>127) in this position
	// indicate garbage data from a misidentified connection.
	if payload[1] > 127 {
		return ""
	}

	// Layer 1: Bound the reader to the actual payload size.
	// ch-go's proto.Reader decodes varint string lengths and pre-allocates
	// that many bytes. With corrupted data, the varint can decode to TB-scale
	// values, causing a fatal OOM that bypasses defer/recover.
	// LimitReader caps reads at len(payload), turning the OOM into io.EOF.
	r := proto.NewReader(io.LimitReader(bytes.NewReader(payload), int64(len(payload))))
	var err error
	if _, err = r.Byte(); err != nil {
		return ""
	}
	if _, err = r.Str(); err != nil {
		return ""
	}
	version := int(proto.FeatureServerQueryTimeInProgress)
	info := proto.ClientInfo{}
	if err = info.DecodeAware(r, version); err != nil {
		return ""
	}
	if info.ProtocolVersion > 0 {
		if info.ProtocolVersion > version {
			return ""
		}
		version = info.ProtocolVersion
	}
	var s proto.Setting

	for {
		if err = s.Decode(r); err != nil {
			return ""
		}
		if s.Key == "" {
			break
		}
	}
	if _, err = r.Str(); err != nil { // inter-server secret
		return ""
	}
	if stage, err := r.UVarInt(); err != nil { // stage
		return ""
	} else if stage > 2 { // invalid stage
		return ""
	}
	if c, err := r.UVarInt(); err != nil { // compression
		return ""
	} else if c > 1 { // invalid compression
		return ""
	}
	l, err := r.StrLen()
	if err != nil {
		return ""
	}
	query := make([]byte, min(l, 1024))
	n, _ := r.Read(query)
	query = bytes.TrimSpace(query[:n])
	if len(query) == 0 {
		return ""
	}
	if n < l {
		query = append(query[:len(query)-1], []byte("...<TRUNCATED>")...)
	}
	return string(query)
}
