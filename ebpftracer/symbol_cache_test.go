package ebpftracer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The cache must key on file identity, not on the path string. Probe paths are
// per-process (/proc/<pid>/root/...) and every pid produces a different string
// for the same file, so a path-keyed cache would miss every time — which is the
// behaviour this cache exists to remove.
func TestLookupSymbolsCachesByFileIdentity(t *testing.T) {
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no /bin/true available")
	}

	first, err := LookupSymbols(bin, []string{"main"})
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	// A second path referring to the same inode must hit the same entry.
	link := filepath.Join(t.TempDir(), "true-hardlink")
	if err := os.Link(bin, link); err != nil {
		t.Skipf("cannot hardlink %s: %v", bin, err)
	}
	second, err := LookupSymbols(link, []string{"main"})
	if err != nil {
		t.Fatalf("lookup via hardlink: %v", err)
	}

	k1, err := binaryKeyFor(bin)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := binaryKeyFor(link)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Fatalf("same file yielded different cache keys:\n  %+v\n  %+v", k1, k2)
	}
	if len(first) != len(second) {
		t.Errorf("cached result differs: %d vs %d entries", len(first), len(second))
	}
}

// A binary that does not export the probe points must be recorded as
// Found=false rather than erroring, so it is never re-parsed. Non-Node
// executables reaching this path are the common case, and re-parsing them per
// pid is what made this hot.
func TestLookupSymbolsCachesNegativeResults(t *testing.T) {
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no /bin/true available")
	}
	targets, err := LookupSymbols(bin, []string{"definitely_not_a_real_symbol_xyzzy"})
	if err != nil {
		t.Fatalf("absent symbol should not error: %v", err)
	}
	got, ok := targets["definitely_not_a_real_symbol_xyzzy"]
	if !ok {
		t.Fatal("absent symbol missing from result map; it must be cached as not-found")
	}
	if got.Found {
		t.Error("absent symbol reported as found")
	}
}

func TestLookupSymbolsUnreadableBinaryIsNotCached(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := LookupSymbols(missing, []string{"main"}); err == nil {
		t.Fatal("expected error for unreadable binary")
	}
	if _, err := binaryKeyFor(missing); err == nil {
		t.Error("expected stat error for missing file")
	}
}

// Distinct binaries must not share an entry.
func TestBinaryKeyDistinguishesFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("aaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("bbbbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	ka, err := binaryKeyFor(a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := binaryKeyFor(b)
	if err != nil {
		t.Fatal(err)
	}
	if ka == kb {
		t.Fatal("different files produced the same cache key")
	}
}
