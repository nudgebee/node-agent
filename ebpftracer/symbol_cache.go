package ebpftracer

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/hashicorp/golang-lru/v2"
)

// ProbeTarget is everything uprobe attachment needs from a symbol: the file
// offset to attach at, and the offsets of the RET instructions inside the
// function for uretprobes.
//
// Both are pure functions of (binary, symbol name) — nothing about them is
// per-process — so they can be resolved once and reused for every process
// running that binary.
type ProbeTarget struct {
	Address       uint64
	ReturnOffsets []int
	Found         bool
}

// binaryKey identifies a file by identity rather than by path.
//
// Paths here are per-process (/proc/<pid>/root/usr/bin/node), so keying the
// cache on the path string would miss for every new pid — exactly the case the
// cache exists to eliminate. Pods from the same image share the read-only
// overlay layer, so dev+inode collapses them onto one entry. Size and mtime
// guard against inode reuse after a delete.
type binaryKey struct {
	dev, ino, size uint64
	mtimeNsec      int64
}

// symbolKey caches one symbol at a time rather than one map per binary.
//
// Keying only by binary and storing the map the first caller happened to ask
// for is wrong: a later caller wanting different symbols from the same file
// would be handed that map and read every one of its own symbols as absent.
// The Node.js and Go-TLS probes can both target the same executable, so this is
// reachable, not theoretical.
type symbolKey struct {
	bin  binaryKey
	name string
}

// Bounded so a node cycling through many image versions cannot grow this
// without limit. Entries are a handful of ints each.
const symbolCacheSize = 4096

var (
	symbolCacheMu sync.Mutex
	symbolCache   *lru.Cache[symbolKey, ProbeTarget]
)

func init() {
	symbolCache, _ = lru.New[symbolKey, ProbeTarget](symbolCacheSize)
}

func binaryKeyFor(path string) (binaryKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return binaryKey{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return binaryKey{}, fmt.Errorf("stat unavailable for %s", path)
	}
	return binaryKey{
		dev:       uint64(st.Dev),
		ino:       uint64(st.Ino),
		size:      uint64(fi.Size()),
		mtimeNsec: fi.ModTime().UnixNano(),
	}, nil
}

// LookupSymbols resolves the named symbols in the binary at path.
//
// On a miss it reads the ELF symbol table and disassembles each function body
// to find its RET instructions; on a hit it does neither. That matters because
// the uncached path is expensive out of proportion to what it yields: node is a
// large statically linked binary, and readSymbols loads the whole .symtab and
// .dynsym — allocating a Go string per symbol — to locate six functions. A
// customer profile showed this at 17.5% of a core, repeated per pid, because
// instrumentNodejs is gated per Process and Node cluster mode runs many
// processes off one binary.
//
// Symbols that are absent are cached with Found=false, deliberately: a binary
// that does not export the probe points must not be re-parsed for every new
// pid. That negative case is the common one, since every non-Node executable
// that reaches here also fails to match.
func LookupSymbols(path string, names []string) (map[string]ProbeTarget, error) {
	key, err := binaryKeyFor(path)
	if err != nil {
		return nil, err
	}

	targets := make(map[string]ProbeTarget, len(names))
	var missing []string
	symbolCacheMu.Lock()
	for _, name := range names {
		if t, ok := symbolCache.Get(symbolKey{bin: key, name: name}); ok {
			targets[name] = t
		} else {
			missing = append(missing, name)
		}
	}
	symbolCacheMu.Unlock()

	if len(missing) == 0 {
		return targets, nil
	}

	// One parse resolves every name still missing, so a partial hit costs no
	// more than a full miss.
	resolved, err := readProbeTargets(path, missing)
	if err != nil {
		// Could not read the binary at all — not cacheable, since a later
		// attempt against a readable path may succeed.
		return nil, err
	}

	symbolCacheMu.Lock()
	for name, t := range resolved {
		symbolCache.Add(symbolKey{bin: key, name: name}, t)
		targets[name] = t
	}
	symbolCacheMu.Unlock()
	return targets, nil
}

// readProbeTargets does the expensive work: one ELF open, one symbol table
// parse shared across all requested names, and one disassembly per found
// symbol.
func readProbeTargets(path string, names []string) (map[string]ProbeTarget, error) {
	ef, err := OpenELFFile(path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()

	targets := make(map[string]ProbeTarget, len(names))
	for _, name := range names {
		s, err := ef.GetSymbol(name)
		if err != nil {
			targets[name] = ProbeTarget{}
			continue
		}
		t := ProbeTarget{Address: s.Address(), Found: true}
		// A symbol with no discoverable RET offsets still attaches an entry
		// uprobe; only the uretprobes are skipped.
		if offsets, err := s.ReturnOffsets(); err == nil {
			t.ReturnOffsets = offsets
		}
		targets[name] = t
	}
	return targets, nil
}

// attachUprobeAt and attachUretprobesAt mirror Symbol.AttachUprobe and
// Symbol.AttachUretprobes, but take a resolved address so attachment no longer
// requires holding an open ELFFile.
func attachUprobeAt(exe *link.Executable, prog *ebpf.Program, pid uint32, addr uint64) (link.Link, error) {
	return exe.Uprobe("", prog, &link.UprobeOptions{Address: addr, PID: int(pid)})
}

func attachUretprobesAt(exe *link.Executable, prog *ebpf.Program, pid uint32, t ProbeTarget) ([]link.Link, error) {
	if len(t.ReturnOffsets) == 0 {
		return nil, fmt.Errorf("no return offsets")
	}
	var links []link.Link
	for _, offset := range t.ReturnOffsets {
		l, err := exe.Uprobe("", prog, &link.UprobeOptions{Address: t.Address + uint64(offset), PID: int(pid)})
		if err != nil {
			return links, err
		}
		links = append(links, l)
	}
	return links, nil
}
