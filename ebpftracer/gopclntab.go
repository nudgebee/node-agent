package ebpftracer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Go keeps a table of every function's name and address range, .gopclntab,
// because the runtime needs it for stack traces and the GC. Release builds
// usually pass -ldflags="-s -w", which drops the ELF symbol table and DWARF
// but cannot drop .gopclntab, so it is the only way to find a function such
// as crypto/tls.(*Conn).Write in a stripped binary.
//
// goFuncTable reads that table in place from a read-only mapping of the
// binary rather than through debug/gosym, which materializes every function
// and allocates hundreds of megabytes for a large binary. The mapped pages
// are mostly already in the page cache, since the binary is running.

var errNoGoFuncTable = errors.New("no .gopclntab")

// pclntab header magics this reader understands (runtime/symtab.go).
const (
	pclntabMagic118 = 0xfffffff0 // Go 1.18-1.19
	pclntabMagic120 = 0xfffffff1 // Go 1.20+
)

type goFuncTable struct {
	mapping   []byte // the whole file, munmapped by close
	pcln      []byte // .gopclntab
	order     binary.ByteOrder
	ptrSize   int
	textStart uint64 // runtime.text: base of the function entry offsets
	textEnd   uint64 // end of .text; a function must lie in [textStart, textEnd)
}

func openGoFuncTable(file *os.File, ef *elf.File) (*goFuncTable, error) {
	sec := ef.Section(".gopclntab")
	if sec == nil {
		// PIE binaries place it in the relocated read-only data.
		sec = ef.Section(".data.rel.ro.gopclntab")
	}
	if sec == nil || sec.Type == elf.SHT_NOBITS {
		return nil, errNoGoFuncTable
	}

	// The mapping outlives file: closing the descriptor does not unmap it.
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 {
		return nil, errNoGoFuncTable
	}
	mapping, err := unix.Mmap(int(file.Fd()), 0, int(info.Size()), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	t := &goFuncTable{mapping: mapping, order: ef.ByteOrder}

	pcln, ok := sectionBytes(mapping, sec)
	if !ok || len(pcln) < 8 {
		t.close()
		return nil, fmt.Errorf(".gopclntab out of file bounds")
	}
	t.pcln = pcln
	switch magic := t.order.Uint32(pcln); magic {
	case pclntabMagic118, pclntabMagic120:
	default:
		t.close()
		return nil, fmt.Errorf("unsupported .gopclntab version 0x%x", magic)
	}
	t.ptrSize = int(pcln[7])
	if t.ptrSize != 4 && t.ptrSize != 8 {
		t.close()
		return nil, fmt.Errorf("unexpected pointer size %d", t.ptrSize)
	}
	text := ef.Section(".text")
	if text == nil {
		t.close()
		return nil, fmt.Errorf("no .text")
	}
	t.textStart = goTextStart(ef, mapping, sec.Addr, t.order, t.ptrSize)
	t.textEnd = text.Addr + text.Size
	return t, nil
}

// goTextStart returns runtime.text, the base that function entry offsets are
// relative to. The header's own textStart field is not filled in by recent
// linkers, so it is read from the runtime's moduledata, found by its first
// field, a pointer to .gopclntab:
//
//	pcHeader; funcnametab, cutab, filetab, pctab, pclntable, ftab (slices);
//	findfunctab; minpc; maxpc; text; ...
//
// so minpc and text are words 20 and 22. With internal linking runtime.text is
// also the start of .text, which is the fallback; with external (cgo) linking
// C startup code comes first, and using .text would shift every function.
func goTextStart(ef *elf.File, mapping []byte, pclnAddr uint64, order binary.ByteOrder, ptrSize int) uint64 {
	text := ef.Section(".text")
	if text == nil {
		return 0
	}
	word := func(b []byte, i int) uint64 {
		if ptrSize == 8 {
			return order.Uint64(b[i:])
		}
		return uint64(order.Uint32(b[i:]))
	}
	for _, sec := range ef.Sections {
		// moduledata is mutable runtime state: it lives in a writable section
		// (.noptrdata, or .go.module in newer toolchains).
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_ALLOC == 0 || sec.Flags&elf.SHF_WRITE == 0 {
			continue
		}
		data, ok := sectionBytes(mapping, sec)
		if !ok {
			continue
		}
		for i := 0; i+23*ptrSize <= len(data); i += ptrSize {
			if word(data, i) != pclnAddr {
				continue
			}
			minpc, textAddr := word(data, i+20*ptrSize), word(data, i+22*ptrSize)
			if minpc == textAddr && textAddr >= text.Addr && textAddr < text.Addr+text.Size {
				return textAddr
			}
		}
	}
	return text.Addr
}

// lookup returns the address range of the named function, or ok=false.
func (t *goFuncTable) lookup(name string) (entry, size uint64, ok bool) {
	ps := t.ptrSize
	hdr := func(i int) (uint64, bool) {
		off := 8 + i*ps
		if off+ps > len(t.pcln) {
			return 0, false
		}
		if ps == 8 {
			return t.order.Uint64(t.pcln[off:]), true
		}
		return uint64(t.order.Uint32(t.pcln[off:])), true
	}
	// Header words after magic/pad/minLC/ptrSize: nfunc, nfiles, textStart,
	// funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset.
	nfunc, ok1 := hdr(0)
	funcnameOff, ok2 := hdr(3)
	pclnOff, ok3 := hdr(7)
	if !ok1 || !ok2 || !ok3 || funcnameOff > uint64(len(t.pcln)) || pclnOff > uint64(len(t.pcln)) {
		return 0, 0, false
	}
	funcnames := t.pcln[funcnameOff:]
	// pclntable starts with the function table: nfunc+1 entries of
	// {entryoff, funcoff uint32}, the last one marking the end of text. Each
	// funcoff points (from the start of pclntable) at a _func whose second
	// field is the offset of its name in funcnametab.
	pclntable := t.pcln[pclnOff:]
	if len(pclntable) < 16 || nfunc == 0 || nfunc > uint64(len(pclntable))/8-1 {
		return 0, 0, false
	}
	want := []byte(name)
	for i := uint64(0); i < nfunc; i++ {
		funcOff := uint64(t.order.Uint32(pclntable[i*8+4:]))
		if funcOff+8 > uint64(len(pclntable)) {
			return 0, 0, false
		}
		nameOff := uint64(t.order.Uint32(pclntable[funcOff+4:]))
		if nameOff+uint64(len(want)) >= uint64(len(funcnames)) {
			continue
		}
		if !bytes.HasPrefix(funcnames[nameOff:], want) || funcnames[nameOff+uint64(len(want))] != 0 {
			continue
		}
		start := uint64(t.order.Uint32(pclntable[i*8:]))
		end := uint64(t.order.Uint32(pclntable[(i+1)*8:]))
		// A uprobe is attached at the entry, and one placed anywhere but an
		// instruction boundary of this binary's code corrupts the traced
		// process: reject any range that does not lie within .text.
		if end <= start || t.textStart+end > t.textEnd {
			return 0, 0, false
		}
		return t.textStart + start, end - start, true
	}
	return 0, 0, false
}

func (t *goFuncTable) close() {
	if t.mapping != nil {
		_ = unix.Munmap(t.mapping)
		t.mapping, t.pcln = nil, nil
	}
}

// sectionBytes returns a section's contents as a slice of the mapped file.
func sectionBytes(mapping []byte, sec *elf.Section) ([]byte, bool) {
	if sec.Type == elf.SHT_NOBITS || sec.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, false
	}
	start, end := sec.Offset, sec.Offset+sec.FileSize
	if end < start || end > uint64(len(mapping)) {
		return nil, false
	}
	return mapping[start:end], true
}
