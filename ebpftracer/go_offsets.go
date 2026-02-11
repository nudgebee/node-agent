package ebpftracer

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"strings"

	"github.com/coroot/coroot-node-agent/common"
	"k8s.io/klog/v2"
)

// GoTLSOffsets contains the offsets needed to extract FD from Go TLS connections.
// These offsets allow the eBPF code to navigate:
// tls.Conn -> conn (net.Conn interface) -> concrete type -> netFD -> poll.FD.Sysfd
//
// Extended to support gRPC connections which wrap net.Conn in credentials.syscallConn
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

	// GRPCSyscallConnItab is the itab address for *credentials.syscallConn implementing net.Conn
	// Used to detect gRPC's connection wrapper
	GRPCSyscallConnItab uint64

	// SyscallConnConnOffset is the offset of 'Conn' field in credentials.syscallConn
	// Used to unwrap gRPC connections
	SyscallConnConnOffset int32

	// Version string for logging
	GoVersion string
}

// GoTLSOffsetsC is the C-compatible struct for the BPF map
// Must match struct go_tls_offsets in gotls.c EXACTLY
// Note: Struct has 4 bytes of tail padding due to uint64 alignment
type GoTLSOffsetsC struct {
	TLSConnConnOffset     int32  // offset 0
	ConnFdOffset          int32  // offset 4
	NetFDPfdOffset        int32  // offset 8
	FDSysfdOffset         int32  // offset 12
	NetTCPConnItab        uint64 // offset 16
	GRPCSyscallConnItab   uint64 // offset 24
	SyscallConnConnOffset int32  // offset 32
	_padding              int32  // offset 36 - tail padding for 8-byte alignment
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
	},
	// Go 1.25+: Potentially different layout (to be verified)
	"1.25": {
		TLSConnConnOffset: 0,
		ConnFdOffset:      0,
		NetFDPfdOffset:    0,
		FDSysfdOffset:     16,
	},
}

// DiscoverGoTLSOffsets attempts to discover Go TLS offsets from a binary.
// It first tries DWARF-based discovery, then falls back to version-based offsets.
// It also discovers itab addresses for gRPC syscallConn support.
func DiscoverGoTLSOffsets(binaryPath string, goVersion string) (*GoTLSOffsets, error) {
	// Try DWARF-based discovery first
	offsets, err := discoverOffsetsFromDWARF(binaryPath)
	if err != nil {
		klog.V(3).Infof("DWARF discovery failed for %s: %v, using version-based fallback", binaryPath, err)
		// Fall back to version-based offsets
		offsets = getVersionBasedOffsets(goVersion)
	}

	offsets.GoVersion = goVersion

	// Discover itab addresses for interface type detection
	// This is critical for gRPC support as gRPC wraps connections in syscallConn
	netTCPItab, grpcSyscallItab, itabErr := DiscoverItabAddresses(binaryPath)
	if itabErr != nil {
		klog.V(3).Infof("Itab discovery failed for %s: %v", binaryPath, itabErr)
	} else {
		offsets.NetTCPConnItab = netTCPItab
		offsets.GRPCSyscallConnItab = grpcSyscallItab

		if grpcSyscallItab != 0 {
			// syscallConn wraps a net.Conn at offset 0 (Conn field is first)
			offsets.SyscallConnConnOffset = 0
			klog.V(2).Infof("Discovered gRPC syscallConn itab at 0x%x for %s", grpcSyscallItab, binaryPath)
		}
	}

	klog.V(2).Infof("Discovered Go TLS offsets: tls_conn=%d, conn_fd=%d, netfd_pfd=%d, fd_sysfd=%d, tcp_itab=0x%x, grpc_itab=0x%x",
		offsets.TLSConnConnOffset, offsets.ConnFdOffset, offsets.NetFDPfdOffset, offsets.FDSysfdOffset,
		offsets.NetTCPConnItab, offsets.GRPCSyscallConnItab)

	return offsets, nil
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

	offsets := &GoTLSOffsets{
		// Set defaults
		TLSConnConnOffset: 0,
		ConnFdOffset:      0,
		NetFDPfdOffset:    0,
		FDSysfdOffset:     16,
	}

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
			if offset, err := getMemberOffset(reader, dwarfData, entry, "pfd"); err == nil {
				offsets.NetFDPfdOffset = int32(offset)
				foundNetFD = true
				klog.V(3).Infof("DWARF: net.netFD.pfd offset = %d", offset)
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
		TLSConnConnOffset:     o.TLSConnConnOffset,
		ConnFdOffset:          o.ConnFdOffset,
		NetFDPfdOffset:        o.NetFDPfdOffset,
		FDSysfdOffset:         o.FDSysfdOffset,
		NetTCPConnItab:        o.NetTCPConnItab,
		GRPCSyscallConnItab:   o.GRPCSyscallConnItab,
		SyscallConnConnOffset: o.SyscallConnConnOffset,
	}
}

// DiscoverItabAddresses finds itab addresses for known interface implementations.
// Itabs are used by Go's runtime to implement interfaces - each interface assignment
// creates an itab that contains type information and method pointers.
func DiscoverItabAddresses(binaryPath string) (netTCPConnItab, grpcSyscallConnItab uint64, err error) {
	ef, err := elf.Open(binaryPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to open ELF: %w", err)
	}
	defer ef.Close()

	symbols, err := ef.Symbols()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read symbols: %w", err)
	}

	// Itab symbols have a specific naming convention:
	// go:itab.*<concrete_type>,<interface_type>
	// Examples:
	// go:itab.*net.TCPConn,net.Conn
	// go:itab.*google.golang.org/grpc/internal/credentials.syscallConn,net.Conn
	for _, sym := range symbols {
		switch {
		case strings.Contains(sym.Name, "go:itab.*net.TCPConn,net.Conn"):
			netTCPConnItab = sym.Value
			klog.V(3).Infof("Found net.TCPConn itab at 0x%x: %s", netTCPConnItab, sym.Name)

		// gRPC's syscallConn can be in different packages depending on gRPC version:
		// - google.golang.org/grpc/credentials.syscallConn (older)
		// - google.golang.org/grpc/internal/credentials.syscallConn (newer)
		case strings.Contains(sym.Name, "syscallConn,net.Conn") &&
			strings.Contains(sym.Name, "grpc"):
			grpcSyscallConnItab = sym.Value
			klog.V(3).Infof("Found gRPC syscallConn itab at 0x%x: %s", grpcSyscallConnItab, sym.Name)
		}
	}

	return netTCPConnItab, grpcSyscallConnItab, nil
}
