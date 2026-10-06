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

	// The address and size come from the binary; never read (or allocate)
	// past the end of .text on the strength of them.
	if s.value < text.Addr || s.size > text.Size || s.value-text.Addr > text.Size-s.size {
		return nil, fmt.Errorf("symbol %s [%#x, +%d) is outside .text", s.name, s.value, s.size)
	}
	sStart := s.value - text.Addr
	_, err = reader.Seek(int64(sStart), io.SeekStart)
	if err != nil {
		return nil, err
	}
	sBytes := make([]byte, s.size)
	_, err = io.ReadFull(reader, sBytes)
	if err != nil {
		return nil, err
	}

	offsets := getReturnOffsets(s.f.elf.Machine, sBytes)
	if len(offsets) == 0 {
		return nil, fmt.Errorf("no offsets found")
	}
	return offsets, nil
}

// StackCheckEnd returns the offset of the first instruction past the
// function's stack check, or 0 if its prologue has none that is recognized.
// See stackCheckEnd.
func (s *Symbol) StackCheckEnd() (int, error) {
	text, reader, err := s.f.getTextSectionAndReader()
	if err != nil {
		return 0, err
	}
	if s.value < text.Addr || s.size > text.Size || s.value-text.Addr > text.Size-s.size {
		return 0, fmt.Errorf("symbol %s [%#x, +%d) is outside .text", s.name, s.value, s.size)
	}
	n := s.size
	if n > stackCheckWindow {
		n = stackCheckWindow
	}
	if _, err := reader.Seek(int64(s.value-text.Addr), io.SeekStart); err != nil {
		return 0, err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(reader, b); err != nil {
		return 0, err
	}
	return stackCheckEnd(s.f.elf.Machine, b), nil
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

// stackCheckWindow bounds the prologue scanned for the stack check: at most
// four instructions precede its branch.
const stackCheckWindow = 32

// stackCheckEnd returns the offset just past a Go function's stack check: the
// compare against the goroutine's stackguard0 and the branch to morestack
// that follows it. 0 if the prologue does not have that shape.
//
// When the stack has to grow, morestack copies it and restarts the function
// from its first instruction, so a probe at the entry fires twice for one
// call; a probe past the branch runs once the check has passed, exactly once
// per call. The argument registers are untouched up to there: the check only
// uses scratch registers (R12 on amd64, R16/R17 on arm64).
func stackCheckEnd(machine elf.Machine, instructions []byte) int {
	switch machine {
	case elf.EM_X86_64:
		// CMPQ SP, 16(R14) or LEAQ -n(SP), R12; CMPQ R12, 16(R14), then JBE.
		compared := false
		for i, k := 0, 0; i < len(instructions) && k < 4; k++ {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err != nil {
				return 0
			}
			i += ins.Len
			switch {
			case ins.Op == x86asm.CMP:
				for _, a := range ins.Args {
					if m, ok := a.(x86asm.Mem); ok && m.Base == x86asm.R14 && m.Disp == 16 {
						compared = true
					}
				}
			case ins.Op == x86asm.JBE && compared:
				return i
			}
		}
	case elf.EM_AARCH64:
		// MOVD 16(g), R16; [SUB $n, RSP, R17;] CMP; BLS.
		loaded := false
		for i, k := 0, 0; i+4 <= len(instructions) && k < 4; i, k = i+4, k+1 {
			ins, err := arm64asm.Decode(instructions[i:])
			if err != nil {
				return 0
			}
			switch {
			case ins.Op == arm64asm.LDR:
				if m, ok := ins.Args[1].(arm64asm.MemImmediate); ok && m.Base == arm64asm.RegSP(arm64asm.X28) {
					loaded = true
				}
			case ins.Op == arm64asm.B && loaded:
				if c, ok := ins.Args[0].(arm64asm.Cond); ok && c.Value == 9 { // LS
					return i + 4
				}
			}
		}
	}
	return 0
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
