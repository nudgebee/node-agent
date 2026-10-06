package l7

import (
	"errors"

	"golang.org/x/net/http2/hpack"
)

// hpackDecoder decodes HPACK header blocks (RFC 7541) like hpack.Decoder,
// except that a reference to a dynamic table entry it does not hold is
// skipped instead of failing the block.
//
// The agent routinely decodes a connection without the peers' full table
// history: it joined the connection after it opened, or a header block was
// lost to truncation. hpack.Decoder fails at the first reference to an entry
// it never saw, so the insertions later in that block are never applied, the
// next block fails the same way, and resetting it changes nothing: once the
// encoder references an old entry on every request, every block of that
// connection fails for good.
//
// Indices count back from the newest entry. Every entry inserted since the
// decoder lost track is therefore at the index the encoder uses, provided no
// insertion is missed. Applying every insertion and skipping only the
// references beyond what the decoder holds converges on the encoder's table
// as its older entries are evicted. A block that was lost (and so its
// insertions) breaks that alignment silently; callers reset the decoder when
// they know a block was lost.
type hpackDecoder struct {
	// dynamic holds the entries the decoder knows, newest last.
	dynamic []hpackEntry
	size    uint32 // RFC 7541 4.1 size of dynamic
	maxSize uint32 // set by dynamic table size updates
}

// hpackEntry is a dynamic table entry. noName marks one inserted by a literal
// whose indexed name the decoder did not hold: its value is known, its name
// is not.
type hpackEntry struct {
	hpack.HeaderField
	noName bool
}

const (
	hpackDefaultTableSize = 4096
	// hpackMaxTableSize bounds what a size update may set. Peers that agreed
	// on a larger SETTINGS_HEADER_TABLE_SIZE use more than 4096; hpack.Decoder
	// rejected their updates.
	hpackMaxTableSize  = 64 * 1024
	hpackEntryOverhead = 32
)

var (
	errHpackTruncated = errors.New("hpack: header block truncated")
	errHpackInvalid   = errors.New("hpack: invalid representation")
)

func newHpackDecoder() *hpackDecoder {
	return &hpackDecoder{maxSize: hpackDefaultTableSize}
}

// reset forgets the dynamic table, for when the caller knows a header block
// was lost and the table no longer matches the encoder's.
func (d *hpackDecoder) reset() {
	clear(d.dynamic) // release the strings the backing array still holds
	d.dynamic = d.dynamic[:0]
	d.size = 0
	d.maxSize = hpackDefaultTableSize
}

// decode decodes one complete header block, calling emit for every field it
// can resolve. unknown counts the fields it could not: references to dynamic
// entries it does not hold, and literals whose indexed name it does not hold
// (their values are still inserted, to keep later indices aligned). An error
// means the block is not valid HPACK, and the table may no longer match.
func (d *hpackDecoder) decode(block []byte, emit func(name, value string)) (unknown int, err error) {
	for len(block) > 0 {
		b := block[0]
		switch {
		case b&0x80 != 0: // 6.1 Indexed Header Field
			var idx uint64
			if idx, block, err = hpackInt(block, 7); err != nil {
				return unknown, err
			}
			if idx == 0 {
				return unknown, errHpackInvalid
			}
			if f, ok := d.field(idx); ok && !f.noName {
				emit(f.Name, f.Value)
			} else {
				unknown++
			}
		case b&0xe0 == 0x20: // 6.3 Dynamic Table Size Update
			var size uint64
			if size, block, err = hpackInt(block, 5); err != nil {
				return unknown, err
			}
			if size > hpackMaxTableSize {
				return unknown, errHpackInvalid
			}
			d.maxSize = uint32(size)
			d.evict(0)
		default: // 6.2 Literal Header Field
			prefix, index := uint8(4), false
			if b&0xc0 == 0x40 { // with incremental indexing
				prefix, index = 6, true
			}
			var nameIdx uint64
			if nameIdx, block, err = hpackInt(block, prefix); err != nil {
				return unknown, err
			}
			var name, value string
			nameKnown := true
			if nameIdx == 0 {
				if name, block, err = hpackString(block); err != nil {
					return unknown, err
				}
			} else if f, ok := d.field(nameIdx); ok && !f.noName {
				name = f.Name
			} else {
				nameKnown = false
			}
			if value, block, err = hpackString(block); err != nil {
				return unknown, err
			}
			if nameKnown {
				emit(name, value)
			} else {
				unknown++
			}
			if index {
				// An entry whose name is unknown still takes its place in the
				// table. Its size is underestimated by the name's length, so it
				// is evicted later than the encoder evicts it: an entry the
				// decoder keeps too long sits past every index the encoder
				// still uses, while one evicted too early would shift them.
				d.insert(hpackEntry{HeaderField: hpack.HeaderField{Name: name, Value: value}, noName: !nameKnown})
			}
		}
	}
	return unknown, nil
}

// field resolves an index into the static table or the known part of the
// dynamic table.
func (d *hpackDecoder) field(idx uint64) (hpackEntry, bool) {
	if idx <= uint64(len(hpackStaticTable)) {
		return hpackEntry{HeaderField: hpackStaticTable[idx-1]}, true
	}
	i := idx - uint64(len(hpackStaticTable)) // 1 = newest
	if i > uint64(len(d.dynamic)) {
		return hpackEntry{}, false
	}
	return d.dynamic[len(d.dynamic)-int(i)], true
}

func (d *hpackDecoder) insert(f hpackEntry) {
	size := uint32(len(f.Name)+len(f.Value)) + hpackEntryOverhead
	if size > d.maxSize {
		// RFC 7541 4.4: an entry larger than the table empties it.
		clear(d.dynamic)
		d.dynamic = d.dynamic[:0]
		d.size = 0
		return
	}
	d.evict(size)
	d.dynamic = append(d.dynamic, f)
	d.size += size
}

// evict drops the oldest entries until room more bytes fit.
func (d *hpackDecoder) evict(room uint32) {
	n := 0
	for d.size+room > d.maxSize && n < len(d.dynamic) {
		f := d.dynamic[n]
		d.size -= uint32(len(f.Name)+len(f.Value)) + hpackEntryOverhead
		n++
	}
	if n > 0 {
		copy(d.dynamic, d.dynamic[n:])
		// Release the evicted strings: the backing array keeps the tail.
		clear(d.dynamic[len(d.dynamic)-n:])
		d.dynamic = d.dynamic[:len(d.dynamic)-n]
	}
}

// hpackInt decodes an RFC 7541 5.1 integer with an n-bit prefix.
func hpackInt(b []byte, n uint8) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, b, errHpackTruncated
	}
	mask := byte(1<<n - 1)
	v := uint64(b[0] & mask)
	b = b[1:]
	if v < uint64(mask) {
		return v, b, nil
	}
	var shift uint
	for i, c := range b {
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b[i+1:], nil
		}
		shift += 7
		if shift > 28 { // nothing in a header block needs more than 32 bits
			return 0, nil, errHpackInvalid
		}
	}
	return 0, nil, errHpackTruncated
}

// hpackString decodes an RFC 7541 5.2 string literal.
func hpackString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", b, errHpackTruncated
	}
	huffman := b[0]&0x80 != 0
	n, b, err := hpackInt(b, 7)
	if err != nil {
		return "", nil, err
	}
	if n > uint64(len(b)) {
		return "", nil, errHpackTruncated
	}
	raw := b[:int(n)]
	b = b[int(n):]
	if !huffman {
		return string(raw), b, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", nil, errHpackInvalid
	}
	return s, b, nil
}

// hpackStaticTable is RFC 7541 Appendix A.
var hpackStaticTable = [...]hpack.HeaderField{
	{Name: ":authority"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"},
	{Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"},
	{Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"},
	{Name: "accept-language"},
	{Name: "accept-ranges"},
	{Name: "accept"},
	{Name: "access-control-allow-origin"},
	{Name: "age"},
	{Name: "allow"},
	{Name: "authorization"},
	{Name: "cache-control"},
	{Name: "content-disposition"},
	{Name: "content-encoding"},
	{Name: "content-language"},
	{Name: "content-length"},
	{Name: "content-location"},
	{Name: "content-range"},
	{Name: "content-type"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "expect"},
	{Name: "expires"},
	{Name: "from"},
	{Name: "host"},
	{Name: "if-match"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "if-range"},
	{Name: "if-unmodified-since"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "max-forwards"},
	{Name: "proxy-authenticate"},
	{Name: "proxy-authorization"},
	{Name: "range"},
	{Name: "referer"},
	{Name: "refresh"},
	{Name: "retry-after"},
	{Name: "server"},
	{Name: "set-cookie"},
	{Name: "strict-transport-security"},
	{Name: "transfer-encoding"},
	{Name: "user-agent"},
	{Name: "vary"},
	{Name: "via"},
	{Name: "www-authenticate"},
}
