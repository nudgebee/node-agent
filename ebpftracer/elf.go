package ebpftracer

import (
	"debug/elf"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// Symbol is a function in an ELF file: its virtual address (value) and size,
// from the ELF symbol tables or, for a stripped Go binary, from .gopclntab.
type Symbol struct {
	name    string
	value   uint64
	size    uint64
	f       *ELFFile
	address uint64
}

func (s *Symbol) Name() string {
	return s.name
}

func (s *Symbol) Address() uint64 {
	if s.address == 0 {
		s.address = s.value
		for _, p := range s.f.elf.Progs {
			if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
				continue
			}
			if p.Vaddr <= s.value && s.value < (p.Vaddr+p.Memsz) {
				s.address = s.value - p.Vaddr + p.Off
				break
			}
		}
	}
	return s.address
}

func (s *Symbol) ReturnOffsets() ([]int, error) {
	text, reader, err := s.f.getTextSectionAndReader()
	if err != nil {
		return nil, err
	}

	sStart := s.value - text.Addr
	_, err = reader.Seek(int64(sStart), io.SeekStart)
	if err != nil {
		return nil, err
	}
	sBytes := make([]byte, s.size)
	_, err = reader.Read(sBytes)
	if err != nil {
		return nil, err
	}

	offsets := getReturnOffsets(s.f.elf.Machine, sBytes)
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no offsets found")
	}
	return offsets, nil
}

func (s *Symbol) AttachUprobe(exe *link.Executable, prog *ebpf.Program, pid uint32) (link.Link, error) {
	return exe.Uprobe("", prog, &link.UprobeOptions{Address: s.Address(), PID: int(pid)})
}

func (s *Symbol) AttachUretprobes(exe *link.Executable, prog *ebpf.Program, pid uint32) ([]link.Link, error) {
	returnOffsets, err := s.ReturnOffsets()
	if err != nil {
		return nil, err
	}
	var links []link.Link
	for _, offset := range returnOffsets {
		l, err := exe.Uprobe("", prog, &link.UprobeOptions{Address: s.Address() + uint64(offset), PID: int(pid)})
		if err != nil {
			return links, err
		}
		links = append(links, l)
	}
	return links, nil
}

type ELFFile struct {
	path              string
	elf               *elf.File
	symbols           []elf.Symbol
	textSection       *elf.Section
	textSectionReader io.ReadSeeker
	goFuncs           *goFuncTable
	goFuncsErr        error
}

func OpenELFFile(path string) (*ELFFile, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return &ELFFile{path: path, elf: file}, nil
}

func (f *ELFFile) readSymbols() error {
	if f.symbols != nil {
		return nil
	}
	symbols, _ := f.elf.Symbols()
	dyn, _ := f.elf.DynamicSymbols()

	if len(symbols) == 0 && len(dyn) == 0 {
		return fmt.Errorf("no symbols found")
	}
	f.symbols = append(symbols, dyn...)
	return nil
}

// GetSymbol finds a function by name in the ELF symbol tables and, failing
// that, in a Go binary's .gopclntab. The fallback covers Go binaries built
// with -ldflags="-s -w": a statically linked one has no symbol table at all,
// and a cgo one keeps only .dynsym, which never lists Go functions.
func (f *ELFFile) GetSymbol(name string) (*Symbol, error) {
	err := f.readSymbols()
	if err == nil {
		for _, s := range f.symbols {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size == 0 || s.Value == 0 {
				continue
			}
			if s.Name == name && s.VersionIndex&0x8000 == 0 {
				return &Symbol{name: s.Name, value: s.Value, size: s.Size, f: f}, nil
			}
		}
		err = fmt.Errorf("symbol %s not found", name)
	}
	if t := f.goFuncTable(); t != nil {
		if entry, size, ok := t.lookup(name); ok {
			return &Symbol{name: name, value: entry, size: size, f: f}, nil
		}
	}
	return nil, err
}

// goFuncTable opens .gopclntab on first use; nil if the file has none or it
// cannot be read.
func (f *ELFFile) goFuncTable() *goFuncTable {
	if f.goFuncs == nil && f.goFuncsErr == nil {
		f.goFuncs, f.goFuncsErr = openGoFuncTable(f.path, f.elf)
	}
	return f.goFuncs
}

func (f *ELFFile) getTextSectionAndReader() (*elf.Section, io.ReadSeeker, error) {
	if f.textSection == nil {
		f.textSection = f.elf.Section(".text")
		if f.textSection == nil {
			return nil, nil, fmt.Errorf("no .text")
		}
		f.textSectionReader = f.textSection.Open()
	}
	return f.textSection, f.textSectionReader, nil
}

func (f *ELFFile) Close() error {
	if f.goFuncs != nil {
		f.goFuncs.close()
	}
	return f.elf.Close()
}

func getReturnOffsets(machine elf.Machine, instructions []byte) []int {
	var res []int
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, i)
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, i)
			}
			i += 4
		}
	}
	return res
}
