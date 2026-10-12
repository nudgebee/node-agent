package ebpftracer

import (
	"debug/elf"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

const gopclntabTestProgram = `package main

import (
	"crypto/tls"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		return
	}
	c, err := tls.Dial("tcp", os.Args[1], nil)
	if err != nil {
		return
	}
	c.Write([]byte(os.Args[2]))
	c.Read(make([]byte, 1))
}
`

// cgoTestProgram links in C so the binary is externally linked and C startup
// code precedes Go's text.
const cgoTestProgram = `package main

// static int one(void) { return 1; }
import "C"

func init() { _ = C.one() }
`

var tlsFuncs = []string{goTlsWriteSymbol, goTlsReadSymbol}

// TestGetSymbol_StrippedGoBinary builds the same program with and without
// -ldflags="-s -w" and checks that every TLS function found through
// .gopclntab in the stripped build matches the ELF symbol table of the
// unstripped one: same entry address and return offsets.
func TestGetSymbol_StrippedGoBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Go binaries")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	src := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module tlsprobe\n\ngo 1.21\n")
	write("main.go", gopclntabTestProgram)

	type variant struct{ arch, mode, cgo string }
	var variants []variant
	for _, arch := range []string{"amd64", "arm64"} {
		for _, mode := range []string{"exe", "pie"} {
			variants = append(variants, variant{arch, mode, "0"})
		}
	}
	// cgo needs a C toolchain for the target, so only the host's own arch.
	if _, err := exec.LookPath("gcc"); err == nil && runtime.GOOS == "linux" {
		for _, mode := range []string{"exe", "pie"} {
			variants = append(variants, variant{runtime.GOARCH, mode, "1"})
		}
	}

	out := t.TempDir()
	build := func(v variant, stripped bool) string {
		name := v.arch + "-" + v.mode + "-cgo" + v.cgo
		ldflags := ""
		if stripped {
			name += "-stripped"
			ldflags = "-s -w"
		}
		bin := filepath.Join(out, name)
		args := []string{"build", "-buildmode=" + v.mode, "-ldflags=" + ldflags, "-o", bin}
		if v.cgo == "1" {
			args = append(args, "-tags=cgoprobe")
		}
		cmd := exec.Command(goBin, append(args, ".")...)
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+v.arch, "CGO_ENABLED="+v.cgo, "GOFLAGS=")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, b)
		}
		return bin
	}

	for _, v := range variants {
		t.Run(v.arch+"-"+v.mode+"-cgo"+v.cgo, func(t *testing.T) {
			if v.cgo == "1" {
				write("cgo.go", "//go:build cgoprobe\n\n"+cgoTestProgram)
			}
			full, stripped := build(v, false), build(v, true)

			sf, err := elf.Open(stripped)
			if err != nil {
				t.Fatal(err)
			}
			if syms, _ := sf.Symbols(); len(syms) != 0 {
				t.Fatalf("stripped build still has %d symtab entries", len(syms))
			}
			sf.Close()

			want, err := OpenELFFile(full)
			if err != nil {
				t.Fatal(err)
			}
			defer want.Close()
			got, err := OpenELFFile(stripped)
			if err != nil {
				t.Fatal(err)
			}
			defer got.Close()

			for _, name := range tlsFuncs {
				ws, err := want.GetSymbol(name)
				if err != nil {
					t.Fatalf("unstripped %s: %v", name, err)
				}
				gs, err := got.GetSymbol(name)
				if err != nil {
					t.Fatalf("stripped %s: %v", name, err)
				}
				if gs.value != ws.value {
					t.Errorf("%s entry = %#x; want %#x", name, gs.value, ws.value)
				}
				// .gopclntab sizes run to the next function, so they include
				// the alignment padding the symbol table leaves out.
				if gs.size < ws.size || gs.size >= ws.size+64 {
					t.Errorf("%s size = %d; want %d plus padding", name, gs.size, ws.size)
				}
				wantRets, err := ws.ReturnOffsets()
				if err != nil {
					t.Fatalf("unstripped %s return offsets: %v", name, err)
				}
				gotRets, err := gs.ReturnOffsets()
				if err != nil {
					t.Fatalf("stripped %s return offsets: %v", name, err)
				}
				if !slices.Equal(gotRets, wantRets) {
					t.Errorf("%s return offsets = %v; want %v", name, gotRets, wantRets)
				}
			}
			if _, err := got.GetSymbol("crypto/tls.(*Conn).NoSuchMethod"); err == nil {
				t.Error("unknown function should not resolve")
			}
		})
	}
}

// A damaged .gopclntab must never panic the agent.
func TestGoFuncTable_CorruptTableDoesNotPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a Go binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module tlsprobe\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(gopclntabTestProgram), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "probe")
	cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	ef, err := OpenELFFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	tab := ef.goFuncTable()
	if tab == nil {
		t.Fatalf("no .gopclntab: %v", ef.goFuncsErr)
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		corrupt := slices.Clone(tab.pcln)
		for j := 0; j < 1+rng.Intn(8); j++ {
			// Concentrate on the header and function table, where a bad value
			// steers every later read.
			corrupt[rng.Intn(min(len(corrupt), 4096))] = byte(rng.Intn(256))
		}
		corrupt = corrupt[:8+rng.Intn(len(corrupt)-8)]
		c := &goFuncTable{pcln: corrupt, order: tab.order, ptrSize: tab.ptrSize, textStart: tab.textStart, textEnd: tab.textEnd}
		for _, name := range tlsFuncs {
			if entry, size, ok := c.lookup(name); ok && (entry < c.textStart || entry+size > c.textEnd) {
				t.Fatalf("%s resolved outside .text: [%#x, +%d)", name, entry, size)
			}
		}
	}
}

// ReturnOffsets reads the function's code from .text; a symbol whose range
// runs outside it must be refused rather than read or allocated for.
func TestReturnOffsets_RejectsSymbolOutsideText(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	ef, err := OpenELFFile(exe)
	if err != nil {
		t.Skip(err)
	}
	defer ef.Close()
	text := ef.elf.Section(".text")
	if text == nil {
		t.Skip("no .text")
	}
	for _, s := range []*Symbol{
		{name: "before", value: text.Addr - 1, size: 16, f: ef},
		{name: "past-end", value: text.Addr + text.Size - 8, size: 16, f: ef},
		{name: "huge", value: text.Addr, size: 1 << 40, f: ef},
		{name: "wraps", value: ^uint64(0) - 4, size: 16, f: ef},
	} {
		if _, err := s.ReturnOffsets(); err == nil {
			t.Errorf("%s: ReturnOffsets should fail for [%#x, +%d)", s.name, s.value, s.size)
		}
	}
}

// A stripped Go binary's symbols come only from .gopclntab. It used to be read
// by reopening the path, a /proc/<pid>/exe link for a process: when the
// process exited between the ELF open and that reopen, its TLS functions were
// "not found", the binary was cached as having none, and every later process
// of it went unprobed. The table is now read through the file already open.
func TestGetSymbol_StrippedGoBinaryAfterPathIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Go binaries")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module tlsprobe\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(gopclntabTestProgram), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "stripped")
	cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", bin, ".")
	cmd.Dir = src
	// An ELF binary whatever the host builds natively.
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	ef, err := OpenELFFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer ef.Close()
	if err := os.Remove(bin); err != nil { // the process exits
		t.Fatal(err)
	}
	for _, name := range tlsFuncs {
		if _, err := ef.GetSymbol(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
