package ebpftracer

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	"github.com/coroot/coroot-node-agent/common"
	lru "github.com/hashicorp/golang-lru/v2"
	"k8s.io/klog/v2"
)

// GoTLSOffsets contains the offsets needed to extract FD from Go TLS connections.
// These offsets allow the eBPF code to navigate:
// tls.Conn -> conn (net.Conn interface) -> concrete type -> netFD -> poll.FD.Sysfd
type GoTLSOffsets struct {
	// TLSConnConnOffset is the offset of the 'conn' field (net.Conn interface) within crypto/tls.Conn
	// Usually 0 since it's the first field
	TLSConnConnOffset int32

	// ConnFdOffset is the offset of the 'fd' field within net.conn
	// net.conn embeds in net.TCPConn/net.UnixConn, and has fd *netFD at offset 0
	ConnFdOffset int32

	// NetFDPfdOffset is the offset of 'pfd' (poll.FD) within net.netFD
	// Usually 0 since pfd is embedded at the start
	NetFDPfdOffset int32

	// FDSysfdOffset is the offset of 'Sysfd' within internal/poll.FD
	// Usually 16 (after fdMutex which is 16 bytes)
	FDSysfdOffset int32

	// NetTCPConnItab is the itab address for *net.TCPConn implementing net.Conn
	// Used to identify the connection type in eBPF
	NetTCPConnItab uint64

	// NetFDFamilyOffset and NetFDSotypeOffset are the offsets of 'family'
	// and 'sotype' within net.netFD. The eBPF walk reads them to check that
	// a connection it found without the itab really is a TCP netFD.
	NetFDFamilyOffset int32
	NetFDSotypeOffset int32

	// Version string for logging
	GoVersion string
}

// GoTLSOffsetsC is the C-compatible struct for the BPF map
// Must match struct go_tls_offsets in gotls.c EXACTLY
type GoTLSOffsetsC struct {
	TLSConnConnOffset int32  // offset 0
	ConnFdOffset      int32  // offset 4
	NetFDPfdOffset    int32  // offset 8
	FDSysfdOffset     int32  // offset 12
	NetTCPConnItab    uint64 // offset 16
	NetFDFamilyOffset int32  // offset 24
	NetFDSotypeOffset int32  // offset 28
}

// knownGoOffsets contains known offsets for different Go versions
// These are fallbacks when DWARF info is not available
var knownGoOffsets = map[string]GoTLSOffsets{
	// Go 1.17-1.24: Standard layout
	"default": {
		TLSConnConnOffset: 0,
		ConnFdOffset:      0,
		NetFDPfdOffset:    0,
		FDSysfdOffset:     16, // fdMutex is 16 bytes (uint64 state + uint32 rsema + uint32 wsema)
		// poll.FD is 56 bytes on 64-bit Linux, and netFD's family and sotype
		// ints follow it.
		NetFDFamilyOffset: 56,
		NetFDSotypeOffset: 64,
	},
	// Go 1.25+: Potentially different layout (to be verified)
	"1.25": {
		TLSConnConnOffset: 0,
		ConnFdOffset:      0,
		NetFDPfdOffset:    0,
		FDSysfdOffset:     16,
		NetFDFamilyOffset: 56,
		NetFDSotypeOffset: 64,
	},
}

var (
	// goTLSOffsetsCache holds the complete result per binary. The itab
	// addresses are per binary, so this is the only level that can answer for
	// a repeat process on its own. A node can start the same handful of Go
	// binaries (CLIs, exec probes) hundreds of times an hour, and without it
	// each start re-read the binary's DWARF and symbol table.
	goTLSOffsetsCache, _ = lru.New[binaryKey, GoTLSOffsets](symbolCacheSize)

	// goStructOffsetsCache holds the DWARF-derived struct offsets per Go
	// version. They describe standard-library types (crypto/tls.Conn,
	// net.netFD, internal/poll.FD), so every binary built by one toolchain
	// shares them, and only the first binary of each version pays for the
	// DWARF parse. That matters on CI nodes, where every `go test` binary is
	// new. The version string includes GOEXPERIMENT tags, so it already
	// separates toolchain variants.
	goStructOffsetsCache, _ = lru.New[string, GoTLSOffsets](64)
)

// DiscoverGoTLSOffsets attempts to discover Go TLS offsets from a binary.
// It first tries DWARF-based discovery, then falls back to version-based offsets.
// It also looks up the binary's *net.TCPConn itab.
//
// Results are cached per binary identity (see binaryKey), so only the first
// process of each binary does the parsing.
func DiscoverGoTLSOffsets(binaryPath string, goVersion string) (*GoTLSOffsets, error) {
	key, keyErr := binaryKeyFor(binaryPath)
	if keyErr == nil {
		if cached, ok := goTLSOffsetsCache.Get(key); ok {
			return &cached, nil
		}
	}

	offsets := structOffsetsFor(binaryPath, goVersion)
	offsets.GoVersion = goVersion

	// The *net.TCPConn itab lets the eBPF walk recognise the connection
	// exactly, rather than by the shape of what it points to.
	netTCPItab, itabErr := DiscoverTCPConnItab(binaryPath)
	if itabErr != nil {
		klog.V(3).Infof("Itab discovery failed for %s: %v", binaryPath, itabErr)
	} else {
		offsets.NetTCPConnItab = netTCPItab
	}

	klog.V(2).Infof("Discovered Go TLS offsets: tls_conn=%d, conn_fd=%d, netfd_pfd=%d, fd_sysfd=%d, netfd_family=%d, netfd_sotype=%d, tcp_itab=0x%x",
		offsets.TLSConnConnOffset, offsets.ConnFdOffset, offsets.NetFDPfdOffset, offsets.FDSysfdOffset,
		offsets.NetFDFamilyOffset, offsets.NetFDSotypeOffset, offsets.NetTCPConnItab)

	// A stripped binary (no .symtab) is a property of the file and is cached
	// like a success. Any other failure is not: it may be transient.
	if keyErr == nil && (itabErr == nil || errors.Is(itabErr, elf.ErrNoSymbols)) {
		goTLSOffsetsCache.Add(key, *offsets)
	}
	return offsets, nil
}

// structOffsetsFor returns the struct offsets for binaries built by goVersion,
// reading binaryPath's DWARF only if no earlier binary of that version has.
func structOffsetsFor(binaryPath, goVersion string) *GoTLSOffsets {
	if cached, ok := goStructOffsetsCache.Get(goVersion); ok {
		return &cached
	}
	offsets, err := discoverOffsetsFromDWARF(binaryPath)
	if err != nil {
		klog.V(3).Infof("DWARF discovery failed for %s: %v, using version-based fallback", binaryPath, err)
		// Not cached: a later binary of the same version may carry DWARF.
		return getVersionBasedOffsets(goVersion)
	}
	goStructOffsetsCache.Add(goVersion, *offsets)
	return offsets
}

// discoverOffsetsFromDWARF extracts struct offsets from DWARF debug info
func discoverOffsetsFromDWARF(binaryPath string) (*GoTLSOffsets, error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF: %w", err)
	}
	defer ef.Close()

	dwarfData, err := ef.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to read DWARF: %w", err)
	}

	defaults := knownGoOffsets["default"]
	offsets := &defaults

	// Track which offsets we successfully discovered
	foundTLSConn := false
	foundNetConn := false
	foundNetFD := false
	foundPollFD := false

	reader := dwarfData.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag != dwarf.TagStructType {
			continue
		}

		name, ok := entry.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}

		switch name {
		case "crypto/tls.Conn":
			if offset, err := getMemberOffset(reader, dwarfData, entry, "conn"); err == nil {
				offsets.TLSConnConnOffset = int32(offset)
				foundTLSConn = true
				klog.V(3).Infof("DWARF: crypto/tls.Conn.conn offset = %d", offset)
			}
		case "net.conn":
			if offset, err := getMemberOffset(reader, dwarfData, entry, "fd"); err == nil {
				offsets.ConnFdOffset = int32(offset)
				foundNetConn = true
				klog.V(3).Infof("DWARF: net.conn.fd offset = %d", offset)
			}
		case "net.netFD":
			members := getMemberOffsets(reader, entry)
			if offset, ok := members["pfd"]; ok {
				offsets.NetFDPfdOffset = int32(offset)
				foundNetFD = true
				klog.V(3).Infof("DWARF: net.netFD.pfd offset = %d", offset)
			}
			if offset, ok := members["family"]; ok {
				offsets.NetFDFamilyOffset = int32(offset)
			}
			if offset, ok := members["sotype"]; ok {
				offsets.NetFDSotypeOffset = int32(offset)
			}
		case "internal/poll.FD":
			if offset, err := getMemberOffset(reader, dwarfData, entry, "Sysfd"); err == nil {
				offsets.FDSysfdOffset = int32(offset)
				foundPollFD = true
				klog.V(3).Infof("DWARF: internal/poll.FD.Sysfd offset = %d", offset)
			}
		}

		// Skip children if we don't need to read members
		if entry.Children {
			reader.SkipChildren()
		}

		// The rest of .debug_info cannot change the answer.
		if foundTLSConn && foundNetConn && foundNetFD && foundPollFD {
			break
		}
	}

	// We need at least the critical FDSysfdOffset
	if !foundPollFD {
		return nil, fmt.Errorf("could not find internal/poll.FD.Sysfd offset in DWARF")
	}

	// Log warnings for offsets we couldn't find (using defaults)
	if !foundTLSConn {
		klog.V(3).Info("DWARF: crypto/tls.Conn.conn not found, using default 0")
	}
	if !foundNetConn {
		klog.V(3).Info("DWARF: net.conn.fd not found, using default 0")
	}
	if !foundNetFD {
		klog.V(3).Info("DWARF: net.netFD.pfd not found, using default 0")
	}

	return offsets, nil
}

// getMemberOffset finds the offset of a struct member
func getMemberOffset(reader *dwarf.Reader, dwarfData *dwarf.Data, structEntry *dwarf.Entry, memberName string) (int64, error) {
	if !structEntry.Children {
		return 0, fmt.Errorf("struct has no children")
	}

	for {
		child, err := reader.Next()
		if err != nil || child == nil {
			break
		}

		if child.Tag == 0 {
			// End of children
			break
		}

		if child.Tag != dwarf.TagMember {
			continue
		}

		name, ok := child.Val(dwarf.AttrName).(string)
		if !ok || name != memberName {
			continue
		}

		// Get the offset
		if offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
			return offset, nil
		}

		// Some DWARF formats use different representations
		return 0, fmt.Errorf("could not read offset for member %s", memberName)
	}

	return 0, fmt.Errorf("member %s not found", memberName)
}

// getMemberOffsets returns the offsets of all members of the struct entry the
// reader has just returned, and leaves the reader past them.
func getMemberOffsets(reader *dwarf.Reader, structEntry *dwarf.Entry) map[string]int64 {
	res := map[string]int64{}
	if !structEntry.Children {
		return res
	}
	for {
		child, err := reader.Next()
		if err != nil || child == nil || child.Tag == 0 {
			return res
		}
		if child.Tag != dwarf.TagMember {
			if child.Children {
				reader.SkipChildren()
			}
			continue
		}
		name, ok := child.Val(dwarf.AttrName).(string)
		if !ok {
			continue
		}
		if offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
			res[name] = offset
		}
	}
}

// getVersionBasedOffsets returns known offsets for a Go version
func getVersionBasedOffsets(goVersion string) *GoTLSOffsets {
	// Parse version to get major.minor
	version := strings.TrimPrefix(goVersion, "go")
	v, err := common.VersionFromString(version)
	if err != nil {
		klog.V(3).Infof("Failed to parse Go version %s: %v, using defaults", goVersion, err)
		offsets := knownGoOffsets["default"]
		return &offsets
	}

	// Check for Go 1.25+
	if v.GreaterOrEqual(common.NewVersion(1, 25, 0)) {
		offsets := knownGoOffsets["1.25"]
		return &offsets
	}

	// Default for Go 1.17-1.24
	offsets := knownGoOffsets["default"]
	return &offsets
}

// ToC converts GoTLSOffsets to the C-compatible struct for BPF map
func (o *GoTLSOffsets) ToC() GoTLSOffsetsC {
	return GoTLSOffsetsC{
		TLSConnConnOffset: o.TLSConnConnOffset,
		ConnFdOffset:      o.ConnFdOffset,
		NetFDPfdOffset:    o.NetFDPfdOffset,
		FDSysfdOffset:     o.FDSysfdOffset,
		NetTCPConnItab:    o.NetTCPConnItab,
		NetFDFamilyOffset: o.NetFDFamilyOffset,
		NetFDSotypeOffset: o.NetFDSotypeOffset,
	}
}

// DiscoverTCPConnItab finds the address of the binary's itab for
// *net.TCPConn implementing net.Conn. Itabs are used by Go's runtime to
// implement interfaces: an interface value holding a *net.TCPConn carries
// this address as its first word.
func DiscoverTCPConnItab(binaryPath string) (uint64, error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open ELF: %w", err)
	}
	defer ef.Close()

	symbols, err := ef.Symbols()
	if err != nil {
		return 0, fmt.Errorf("failed to read symbols: %w", err)
	}

	// Itab symbols are named go:itab.*<concrete type>,<interface type>.
	for _, sym := range symbols {
		if strings.Contains(sym.Name, "go:itab.*net.TCPConn,net.Conn") {
			klog.V(3).Infof("Found net.TCPConn itab at 0x%x: %s", sym.Value, sym.Name)
			return sym.Value, nil
		}
	}
	return 0, nil
}
