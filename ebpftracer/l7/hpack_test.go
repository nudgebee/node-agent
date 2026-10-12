package l7

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// requestHeaders is a header list shaped like real traffic: a few stable
// headers the encoder indexes once and references from then on, a path from a
// small set, and a per-request ID that is inserted every time and so turns the
// dynamic table over.
func requestHeaders(i int) []hpack.HeaderField {
	return []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "api.example.com"},
		{Name: ":path", Value: fmt.Sprintf("/v1/items/%d", i%7)},
		{Name: "user-agent", Value: "client/1.2.3"},
		{Name: "x-request-id", Value: fmt.Sprintf("req-%08d-%08d", i, i*7919)},
	}
}

func encodeBlocks(t testing.TB, n int, headers func(int) []hpack.HeaderField) [][]byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	blocks := make([][]byte, n)
	for i := range blocks {
		buf.Reset()
		for _, f := range headers(i) {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		blocks[i] = append([]byte(nil), buf.Bytes()...)
	}
	return blocks
}

func decodeAll(t testing.TB, d *hpackDecoder, block []byte) ([]hpack.HeaderField, int) {
	var got []hpack.HeaderField
	unknown, err := d.decode(block, func(name, value string) {
		got = append(got, hpack.HeaderField{Name: name, Value: value})
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got, unknown
}

func sameFields(a, b []hpack.HeaderField) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

// With the whole connection seen, the decoder must decode exactly what
// hpack.Decoder decodes, across indexing modes, Huffman coding, evictions and
// table size updates.
func TestHpackDecoderMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	ref := hpack.NewDecoder(hpackDefaultTableSize, nil)
	d := newHpackDecoder()
	for i := 0; i < 2000; i++ {
		buf.Reset()
		if i%300 == 150 {
			enc.SetMaxDynamicTableSize(uint32(256 + rng.Intn(3840)))
		}
		var want []hpack.HeaderField
		for j := 0; j < 1+rng.Intn(12); j++ {
			f := hpack.HeaderField{
				Name:      fmt.Sprintf("x-h%d", rng.Intn(20)),
				Value:     fmt.Sprintf("%x", rng.Int63n(1<<uint(1+rng.Intn(40)))),
				Sensitive: rng.Intn(10) == 0,
			}
			if rng.Intn(4) == 0 {
				f = requestHeaders(rng.Intn(50))[rng.Intn(6)]
			}
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
			want = append(want, hpack.HeaderField{Name: f.Name, Value: f.Value})
		}
		refFields, err := ref.DecodeFull(buf.Bytes())
		if err != nil {
			t.Fatalf("block %d: reference decoder: %v", i, err)
		}
		got, unknown := decodeAll(t, d, buf.Bytes())
		if unknown != 0 {
			t.Fatalf("block %d: %d unknown fields with the whole connection seen", i, unknown)
		}
		for k := range refFields {
			refFields[k].Sensitive = false
		}
		if !sameFields(got, refFields) || !sameFields(got, want) {
			t.Fatalf("block %d:\n got  %v\n want %v", i, got, want)
		}
	}
}

// staticName reports whether a header name is in the static table. Literals
// with such a name take it from there, so it is always known; a custom name
// (x-request-id) is taken from the newest entry with that name, and if that
// chain began before the decoder joined, its name stays unknown.
func staticName(name string) bool {
	for _, f := range hpackStaticTable {
		if f.Name == name {
			return true
		}
	}
	return false
}

func withStaticNames(fs []hpack.HeaderField) []hpack.HeaderField {
	var out []hpack.HeaderField
	for _, f := range fs {
		if staticName(f.Name) {
			out = append(out, hpack.HeaderField{Name: f.Name, Value: f.Value})
		}
	}
	return out
}

// Joining a connection after its first requests: hpack.Decoder, reset after
// every error as the parser used to, fails on every block for good, because
// each block references stable headers inserted before it joined before it
// reaches anything new. The tolerant decoder skips those references, applies
// every insertion, and decodes every static-named header (the pseudo-headers,
// content-type, ...) once the encoder has turned its table over.
func TestHpackDecoderRecoversAfterJoiningMidStream(t *testing.T) {
	const join, n = 20, 400
	blocks := encodeBlocks(t, n, requestHeaders)

	ref := hpack.NewDecoder(hpackDefaultTableSize, nil)
	full := hpack.NewDecoder(hpackDefaultTableSize, nil)
	d := newHpackDecoder()
	refErrors, recoveredAt := 0, -1
	for i, block := range blocks {
		want, err := full.DecodeFull(block)
		if err != nil {
			t.Fatal(err)
		}
		if i < join {
			continue
		}
		if _, err := ref.DecodeFull(block); err != nil {
			refErrors++
			ref = hpack.NewDecoder(hpackDefaultTableSize, nil)
		}

		got, unknown := decodeAll(t, d, block)
		if len(got)+unknown != len(want) {
			t.Fatalf("block %d: %d decoded + %d unknown, want %d fields", i, len(got), unknown, len(want))
		}
		// Every field it does decode must be the right one: a subsequence of
		// the true list, in order.
		k := 0
		for _, f := range want {
			if k < len(got) && got[k].Name == f.Name && got[k].Value == f.Value {
				k++
			}
		}
		if k != len(got) {
			t.Fatalf("block %d: decoded %v, not a subsequence of %v", i, got, want)
		}
		complete := sameFields(withStaticNames(got), withStaticNames(want))
		if complete && recoveredAt < 0 {
			recoveredAt = i
		}
		if recoveredAt >= 0 && !complete {
			t.Fatalf("block %d: static-named headers missing after recovering at block %d: got %v, want %v", i, recoveredAt, got, want)
		}
	}
	if recoveredAt < 0 {
		t.Fatal("never recovered")
	}
	t.Logf("tolerant decoder complete from block %d; reset-on-error decoder failed %d of %d blocks", recoveredAt, refErrors, n-join)
	if refErrors != n-join {
		t.Fatalf("reference decoder failed %d of %d blocks; this test no longer shows the cascade", refErrors, n-join)
	}
}

// A literal whose indexed name the decoder does not hold still inserts an
// entry; skipping the insertion would shift every older index by one and
// decode later references to the wrong header.
func TestHpackDecoderKeepsAlignmentThroughUnknownNames(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	write := func(fs ...hpack.HeaderField) []byte {
		buf.Reset()
		for _, f := range fs {
			if err := enc.WriteField(f); err != nil {
				t.Fatal(err)
			}
		}
		return append([]byte(nil), buf.Bytes()...)
	}
	write(hpack.HeaderField{Name: "x-custom", Value: "a"}) // before the join
	d := newHpackDecoder()
	// Name from the unknown entry, new value: inserted with an unknown name.
	b1 := write(hpack.HeaderField{Name: "x-custom", Value: "b"})
	b2 := write(hpack.HeaderField{Name: "x-other", Value: "c"})
	b3 := write(hpack.HeaderField{Name: "x-other", Value: "c"}, hpack.HeaderField{Name: "x-custom", Value: "b"})

	if got, unknown := decodeAll(t, d, b1); len(got) != 0 || unknown != 1 {
		t.Fatalf("b1: got %v, %d unknown", got, unknown)
	}
	decodeAll(t, d, b2)
	got, unknown := decodeAll(t, d, b3)
	if unknown != 1 || len(got) != 1 || got[0].Name != "x-other" || got[0].Value != "c" {
		t.Fatalf("b3: got %v, %d unknown; want x-other: c and one unknown", got, unknown)
	}
}

// Peers that agreed on a larger SETTINGS_HEADER_TABLE_SIZE send larger size
// updates; hpack.Decoder(4096) rejected them.
func TestHpackDecoderAcceptsLargerTable(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	enc.SetMaxDynamicTableSizeLimit(16384)
	enc.SetMaxDynamicTableSize(16384)
	if err := enc.WriteField(hpack.HeaderField{Name: "x-a", Value: "1"}); err != nil {
		t.Fatal(err)
	}
	got, unknown := decodeAll(t, newHpackDecoder(), buf.Bytes())
	if unknown != 0 || len(got) != 1 || got[0].Value != "1" {
		t.Fatalf("got %v, %d unknown", got, unknown)
	}
}

func TestHpackDecoderRejectsMalformedBlocks(t *testing.T) {
	for name, block := range map[string][]byte{
		"index 0":           {0x80},
		"truncated integer": {0xff, 0x80},
		"truncated string":  {0x40, 0x05, 'a'},
		"integer overflow":  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"bad huffman":       {0x40, 0x81, 0xff, 0x00},
	} {
		if _, err := newHpackDecoder().decode(block, func(string, string) {}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// Random bytes must never panic.
	rng := rand.New(rand.NewSource(2))
	d := newHpackDecoder()
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(64))
		rng.Read(b)
		if _, err := d.decode(b, func(string, string) {}); err != nil {
			d.reset()
		}
	}
}

func BenchmarkHpackDecoder(b *testing.B) {
	blocks := encodeBlocks(b, 1000, requestHeaders)
	emit := func(string, string) {}
	b.Run("tolerant", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			d := newHpackDecoder()
			for _, block := range blocks {
				if _, err := d.decode(block, emit); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("x/net", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			d := hpack.NewDecoder(hpackDefaultTableSize, func(hpack.HeaderField) {})
			for _, block := range blocks {
				if _, err := d.Write(block); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// A size update above what the decoder will hold is clamped, not an error
// that would lose the rest of the block.
func TestHpackDecoderClampsOversizedTableUpdate(t *testing.T) {
	block := []byte{0x3f, 0xe1, 0xff, 0x7f} // size update to ~2 MiB
	var buf bytes.Buffer
	_ = hpack.NewEncoder(&buf).WriteField(hpack.HeaderField{Name: "x-a", Value: "1"})
	block = append(block, buf.Bytes()...)
	d := newHpackDecoder()
	got, unknown := decodeAll(t, d, block)
	if unknown != 0 || len(got) != 1 || got[0].Value != "1" {
		t.Fatalf("got %v, %d unknown", got, unknown)
	}
	if d.maxSize != hpackMaxTableSize {
		t.Errorf("maxSize = %d, want %d", d.maxSize, hpackMaxTableSize)
	}
}

// A 64 KB block of minimal insertions after a size update to 64 KiB evicts
// on every insertion once the table is full. With a slice that shifted per
// eviction this took ~34 ms; the ring makes it linear.
func manySmallInsertions() []byte {
	var b bytes.Buffer
	b.Write([]byte{0x3f, 0xe1, 0xff, 0x03}) // size update to 64 KiB
	for b.Len() < 64*1024 {
		b.Write([]byte{0x40, 0x01, 'a', 0x00}) // literal with indexing, name "a", empty value
	}
	return b.Bytes()
}

func BenchmarkHpackDecoderManySmallInsertions(b *testing.B) {
	block := manySmallInsertions()
	emit := func(string, string) {}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := newHpackDecoder().decode(block, emit); err != nil {
			b.Fatal(err)
		}
	}
}
