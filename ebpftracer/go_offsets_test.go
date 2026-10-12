package ebpftracer

import (
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// goRuntimeOffsets reads the same offsets as discoverOffsetsFromDWARF,
// but from the running binary's type information, which the compiler
// guarantees. The test binary is built by the same toolchain it inspects, so
// the two must agree.
func goRuntimeOffsets(t *testing.T) GoTLSOffsets {
	field := func(typ reflect.Type, name string) reflect.StructField {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("%s has no field %s", typ, name)
		}
		return f
	}
	conn := field(reflect.TypeOf((*net.TCPConn)(nil)).Elem(), "conn")
	fd := field(conn.Type, "fd")
	pfd := field(fd.Type.Elem(), "pfd")
	sysfd := field(pfd.Type, "Sysfd")
	return GoTLSOffsets{
		TLSConnConnOffset: int32(field(reflect.TypeOf((*tls.Conn)(nil)).Elem(), "conn").Offset),
		ConnFdOffset:      int32(fd.Offset),
		NetFDPfdOffset:    int32(pfd.Offset),
		FDSysfdOffset:     int32(sysfd.Offset),
		NetFDFamilyOffset: int32(field(fd.Type.Elem(), "family").Offset),
		NetFDSotypeOffset: int32(field(fd.Type.Elem(), "sotype").Offset),
	}
}

// The walk stops as soon as all four structs are found. That must not change
// what it finds.
func TestDiscoverOffsetsFromDWARFMatchesRuntimeLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a Go binary")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not found")
	}
	// `go test` links without DWARF, so build a binary that has it.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module tlsprobe\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(gopclntabTestProgram), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "tlsprobe")
	cmd := exec.Command(goBin, "build", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}

	got, err := discoverOffsetsFromDWARF(bin)
	if err != nil {
		t.Fatal(err)
	}
	want := goRuntimeOffsets(t)
	if *got != want {
		t.Fatalf("DWARF offsets differ from the runtime layout:\n  dwarf:   %+v\n  runtime: %+v", *got, want)
	}
}

// Stripped binaries get the version table, and for them the eBPF walk trusts
// a connection found without the itab only if netFD's family and sotype read
// as a TCP socket's. The table must describe the toolchain that builds this
// test; a Go release that changes poll.FD or net.netFD fails here first.
func TestVersionOffsetsMatchRuntimeLayout(t *testing.T) {
	got := *getVersionBasedOffsets(runtime.Version())
	want := goRuntimeOffsets(t)
	if got != want {
		t.Fatalf("version table offsets differ from the runtime layout of %s:\n  table:   %+v\n  runtime: %+v", runtime.Version(), got, want)
	}
}

// A repeat process of a binary must be served from the cache, not by reading
// DWARF and the symbol table again. Re-reading them was 18-52% of the agent's
// CPU on busy nodes.
func TestDiscoverGoTLSOffsetsCachesPerBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if _, err := DiscoverGoTLSOffsets(exe, runtime.Version()); err != nil {
		t.Fatal(err)
	}
	key, err := binaryKeyFor(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !goTLSOffsetsCache.Contains(key) {
		t.Fatal("result was not cached for the binary")
	}

	// Replace the entry with a value no parse could produce: getting it back
	// proves the second call never looked at the file.
	sentinel := GoTLSOffsets{FDSysfdOffset: 12345, GoVersion: runtime.Version()}
	goTLSOffsetsCache.Add(key, sentinel)
	got, err := DiscoverGoTLSOffsets(exe, runtime.Version())
	if err != nil {
		t.Fatal(err)
	}
	if *got != sentinel {
		t.Fatalf("second call re-parsed the binary: got %+v", *got)
	}
}

// Struct offsets describe standard-library types, so a binary whose Go version
// was already seen must reuse them instead of reading its own DWARF. On CI
// nodes every `go test` binary is new, so the per-binary cache never hits.
func TestStructOffsetsSharedAcrossBinariesOfOneVersion(t *testing.T) {
	const version = "go1.99.0-shared-test"
	sentinel := GoTLSOffsets{FDSysfdOffset: 777}
	goStructOffsetsCache.Add(version, sentinel)

	// Not an ELF file: any attempt to read its DWARF would fail and fall back
	// to the version table (16).
	bin := filepath.Join(t.TempDir(), "not-elf")
	if err := os.WriteFile(bin, []byte("not an elf file"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DiscoverGoTLSOffsets(bin, version)
	if err != nil {
		t.Fatal(err)
	}
	if got.FDSysfdOffset != sentinel.FDSysfdOffset {
		t.Fatalf("FDSysfdOffset = %d, want %d from the per-version cache", got.FDSysfdOffset, sentinel.FDSysfdOffset)
	}

	// The symbol table could not be read for a reason other than stripping,
	// which may be transient, so the binary itself must not be cached.
	key, err := binaryKeyFor(bin)
	if err != nil {
		t.Fatal(err)
	}
	if goTLSOffsetsCache.Contains(key) {
		t.Error("binary with an unreadable symbol table was cached")
	}
}

// When DWARF is unavailable the version-table fallback must not be cached
// under the version, or one stripped binary would stop every later binary of
// that version from being read.
func TestStructOffsetsFallbackIsNotCachedByVersion(t *testing.T) {
	const version = "go1.99.1-fallback-test"
	bin := filepath.Join(t.TempDir(), "not-elf")
	if err := os.WriteFile(bin, []byte("not an elf file"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := structOffsetsFor(bin, version)
	if got.FDSysfdOffset != knownGoOffsets["1.25"].FDSysfdOffset {
		t.Fatalf("fallback FDSysfdOffset = %d", got.FDSysfdOffset)
	}
	if goStructOffsetsCache.Contains(version) {
		t.Fatal("fallback offsets were cached under the version")
	}
}
