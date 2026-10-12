package l7

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// Revisions at which the layout of a Query packet changes, from ClickHouse's
// src/Core/ProtocolDefines.h. The layout follows the revision negotiated in
// the handshake, min(client, server), which the packet doesn't carry.
const (
	chRevInitialQueryStartTime = 54449
	chRevParallelReplicas      = 54453
	chRevParameters            = 54459
	chRevExternalRoles         = 54472
	chRevQueryAndLineNumbers   = 54475
	chRevJWT                   = 54476
	chRevClientAgent           = 54485
	chRevInternalQueryFlag     = 54486
	chRevCurrentRoles          = 54488
	chRevHTTPHandler           = 54490
)

// chLayouts are the revisions to try, newest first: one per distinct layout
// from chRevInitialQueryStartTime on, which the eBPF detection requires.
var chLayouts = []uint64{
	chRevHTTPHandler, chRevCurrentRoles, chRevInternalQueryFlag, chRevClientAgent, chRevJWT,
	chRevQueryAndLineNumbers, chRevExternalRoles, chRevParameters, chRevParallelReplicas,
	chRevInitialQueryStartTime,
}

const (
	chClientData             = 2
	chClientScalar           = 7
	chClientIgnoredPartUUIDs = 8
	chClientQueryPlan        = 13
	chQueryKindInitial       = 1
	chQueryKindSecond        = 2
	chInterfaceTCP           = 1
	chInterfaceHTTP          = 2
	chInterfaceMax           = 11 // ICEBERG_REST_CATALOG
	chMaxQuerySize           = 1024
)

type chReader struct {
	data []byte
	off  int
}

func (r *chReader) uvarint() (uint64, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	v, n := binary.Uvarint(r.data[r.off:])
	if n <= 0 {
		return 0, false
	}
	r.off += n
	return v, true
}

func (r *chReader) byte() (byte, bool) {
	if r.off >= len(r.data) {
		return 0, false
	}
	b := r.data[r.off]
	r.off++
	return b, true
}

func (r *chReader) skip(n int) bool {
	if n < 0 || n > len(r.data)-r.off {
		return false
	}
	r.off += n
	return true
}

func (r *chReader) skipStr() bool {
	l, ok := r.uvarint()
	return ok && l <= uint64(len(r.data)-r.off) && r.skip(int(l))
}

func (r *chReader) skipStrings(n int) bool {
	for i := 0; i < n; i++ {
		if !r.skipStr() {
			return false
		}
	}
	return true
}

func (r *chReader) skipUvarints(n int) bool {
	for i := 0; i < n; i++ {
		if _, ok := r.uvarint(); !ok {
			return false
		}
	}
	return true
}

func (r *chReader) flag() (byte, bool) {
	b, ok := r.byte()
	return b, ok && b <= 1
}

// chQueryEnd reports whether b, the bytes after the query, may be cut short,
// starts as a Query packet ends: query parameters, then one of the packets
// that follow a Query (src/Client/Connection.cpp).
func chQueryEnd(b []byte, rev uint64) bool {
	r := &chReader{data: b}
	if rev >= chRevParameters {
		for {
			if r.off == len(r.data) {
				return true
			}
			start := r.off
			end, ok := r.settingName()
			if !ok {
				return chName(r.data[start:]) // cut short, or not a name
			}
			if end {
				break
			}
			if _, ok = r.uvarint(); !ok { // flags
				return true
			}
			if !r.skipStr() { // value
				return true
			}
		}
	}
	if r.off == len(r.data) {
		return true
	}
	switch r.data[r.off] {
	case chClientData, chClientScalar: // a block, after the name of its table or scalar
		return chName(r.data[r.off+1:])
	case chClientIgnoredPartUUIDs, chClientQueryPlan:
		return true
	}
	return false
}

// chName reports whether b, which may be cut short, starts with a
// length-prefixed identifier, possibly empty.
func chName(b []byte) bool {
	l, n := binary.Uvarint(b)
	if n <= 0 {
		return n == 0 // cut inside the length
	}
	name := b[n:]
	if uint64(len(name)) > l {
		name = name[:l]
	}
	for _, c := range name {
		if !isIdentByte(c) {
			return false
		}
	}
	return true
}

// hasControlBytes reports whether b has a control character other than tab,
// CR or LF, which query text doesn't.
func hasControlBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
			return true
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// settingName skips the name of a setting or a query parameter, which is an
// identifier; an empty name ends the list. A name that isn't an identifier
// means the packet was read with the wrong layout.
func (r *chReader) settingName() (end bool, ok bool) {
	l, ok := r.uvarint()
	if !ok || l > uint64(len(r.data)-r.off) {
		return false, false
	}
	for _, c := range r.data[r.off : r.off+int(l)] {
		if !isIdentByte(c) {
			return false, false
		}
	}
	r.off += int(l)
	return l == 0, true
}

// ParseClickhouse returns the query text of a native protocol Query packet.
// ok is false when the payload isn't a Query packet. A Query packet whose
// layout isn't one of chLayouts, or whose query can't be read, gives ok with
// an empty query: the connection is still ClickHouse.
func ParseClickhouse(payload []byte) (query string, ok bool) {
	r := &chReader{data: payload}
	if _, ok := r.byte(); !ok { // packet type (Query)
		return "", false
	}
	if !r.skipStr() { // query id
		return "", false
	}
	kind, ok := r.byte()
	if !ok || (kind != chQueryKindInitial && kind != chQueryKindSecond) {
		return "", false
	}
	if !r.skipStrings(3) { // initial user, initial query id, initial address
		return "", false
	}
	if !r.skip(8) { // initial query start time
		return "", false
	}
	iface, ok := r.byte()
	if !ok || iface < chInterfaceTCP || iface > chInterfaceMax {
		return "", false
	}
	var clientRevision uint64
	switch iface {
	case chInterfaceTCP:
		if !r.skipStrings(3) { // os user, client hostname, client name
			return "", false
		}
		if !r.skipUvarints(2) { // client version major, minor
			return "", false
		}
		if clientRevision, ok = r.uvarint(); !ok {
			return "", false
		}
	case chInterfaceHTTP:
		if !r.skip(1) { // HTTP method
			return "", false
		}
		if !r.skipStrings(3) { // user agent, X-Forwarded-For, referer
			return "", false
		}
	}
	// The client's own revision bounds the negotiated one, so layouts at or
	// below it go first. It is only a hint: a server forwarding a secondary
	// query sends the initiator's client info, and some clients report 0.
	for pass := 0; pass < 2; pass++ {
		for _, rev := range chLayouts {
			if rev == chRevHTTPHandler && iface != chInterfaceHTTP {
				continue // the same layout as chRevCurrentRoles
			}
			if (rev <= clientRevision) != (pass == 0) {
				continue
			}
			t := *r
			if q, ok := t.query(rev, iface); ok {
				return q, true
			}
		}
	}
	return "", true
}

// query reads the rest of a Query packet, laid out for revision rev.
func (r *chReader) query(rev uint64, iface byte) (string, bool) {
	if iface == chInterfaceHTTP && rev >= chRevHTTPHandler {
		if !r.skipStrings(2) { // HTTP handler name, request URL
			return "", false
		}
	}
	if !r.skipStr() { // quota key
		return "", false
	}
	if !r.skipUvarints(1) { // distributed depth
		return "", false
	}
	if iface == chInterfaceTCP && !r.skipUvarints(1) { // client version patch
		return "", false
	}
	if hasTrace, ok := r.flag(); !ok { // OpenTelemetry context
		return "", false
	} else if hasTrace == 1 {
		if !r.skip(16 + 8) { // trace id, span id
			return "", false
		}
		if !r.skipStr() { // trace state
			return "", false
		}
		if !r.skip(1) { // trace flags
			return "", false
		}
	}
	if rev >= chRevParallelReplicas {
		if _, ok := r.flag(); !ok { // collaborate with initiator
			return "", false
		}
		if !r.skipUvarints(2) { // count of participating replicas, number of the current replica
			return "", false
		}
	}
	if rev >= chRevQueryAndLineNumbers && !r.skipUvarints(2) { // script query number, line number
		return "", false
	}
	if rev >= chRevJWT {
		if hasJWT, ok := r.flag(); !ok || (hasJWT == 1 && !r.skipStr()) {
			return "", false
		}
	}
	if rev >= chRevClientAgent && !r.skipStr() {
		return "", false
	}
	if rev >= chRevInternalQueryFlag {
		if _, ok := r.flag(); !ok {
			return "", false
		}
	}
	if rev >= chRevCurrentRoles {
		hasRoles, ok := r.flag()
		if !ok {
			return "", false
		}
		if hasRoles == 1 {
			n, ok := r.uvarint()
			if !ok || n > uint64(len(r.data)-r.off) || !r.skipStrings(int(n)) {
				return "", false
			}
		}
	}

	for { // settings
		end, ok := r.settingName()
		if !ok {
			return "", false
		}
		if end {
			break
		}
		if _, ok = r.uvarint(); !ok { // flags
			return "", false
		}
		if !r.skipStr() { // value
			return "", false
		}
	}
	if rev >= chRevExternalRoles && !r.skipStr() {
		return "", false
	}
	if !r.skipStr() { // inter-server secret
		return "", false
	}
	if stage, ok := r.uvarint(); !ok || stage > 2 {
		return "", false
	}
	if compression, ok := r.uvarint(); !ok || compression > 1 {
		return "", false
	}

	l, ok := r.uvarint() // query size
	if !ok || r.off > len(r.data) {
		return "", false
	}
	query := r.data[r.off:]
	if uint64(len(query)) > l {
		query = query[:l]
		// What follows the query shows whether the layout was right.
		if !chQueryEnd(r.data[r.off+int(l):], rev) {
			return "", false
		}
	}
	if len(query) > chMaxQuerySize {
		query = query[:chMaxQuerySize]
	}
	truncated := uint64(len(query)) < l
	query = bytes.TrimSpace(query)
	if truncated && len(query) > 0 {
		// The cut can land inside a multi-byte character: drop it before
		// validating. A partial character is at most utf8.UTFMax-1 bytes.
		query = query[:len(query)-1]
		for i := 0; i < utf8.UTFMax-1 && len(query) > 0; i++ {
			if r, size := utf8.DecodeLastRune(query); r != utf8.RuneError || size > 1 {
				break
			}
			query = query[:len(query)-1]
		}
	}
	if len(query) == 0 {
		return "", false
	}
	if !utf8.Valid(query) || hasControlBytes(query) { // misaligned or corrupted
		return "", false
	}
	if truncated {
		return string(query) + "...<TRUNCATED>", true
	}
	return string(query), true
}
