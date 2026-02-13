package ebpftracer

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"k8s.io/klog/v2"
)

// SocketInfoOffsets mirrors the eBPF struct socket_info_offsets
// Must match exactly for binary.Write to work correctly
type SocketInfoOffsets struct {
	// task_struct offsets
	TaskFilesOffset int32 // task_struct->files

	// files_struct offsets
	FilesFdtOffset int32 // files_struct->fdt

	// fdtable offsets
	FdtFdOffset     int32 // fdtable->fd (pointer to fd array)
	FdtMaxFdsOffset int32 // fdtable->max_fds

	// file offsets
	FilePrivateDataOffset int32 // file->private_data

	// socket offsets
	SocketSkOffset int32 // socket->sk

	// sock_common offsets (connection tuple)
	SkFamilyOffset     int32 // sock_common->skc_family
	SkDaddrOffset      int32 // sock_common->skc_daddr (IPv4 dest)
	SkRcvSaddrOffset   int32 // sock_common->skc_rcv_saddr (IPv4 src)
	SkDportOffset      int32 // sock_common->skc_dport
	SkNumOffset        int32 // sock_common->skc_num (src port)
	SkV6DaddrOffset    int32 // sock_common->skc_v6_daddr (IPv6 dest)
	SkV6RcvSaddrOffset int32 // sock_common->skc_v6_rcv_saddr (IPv6 src)

	// Flags
	OffsetsValid uint8
	Padding      [3]uint8
}

// discoverSocketOffsets uses BTF to discover kernel struct offsets
func discoverSocketOffsets() (*SocketInfoOffsets, error) {
	// Load kernel BTF
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	offsets := &SocketInfoOffsets{}

	// Helper function to get field offset from a struct
	getOffset := func(typeName, fieldName string) (int32, error) {
		var st *btf.Struct
		if err := spec.TypeByName(typeName, &st); err != nil {
			return 0, fmt.Errorf("type %s not found: %w", typeName, err)
		}

		for _, m := range st.Members {
			if m.Name == fieldName {
				return int32(m.Offset / 8), nil
			}
		}
		return 0, fmt.Errorf("field %s not found in %s", fieldName, typeName)
	}

	// Helper to recursively search for field in struct (handles anonymous unions/structs)
	var getOffsetRecursive func(st *btf.Struct, fieldName string, baseOffset uint32) (int32, bool)
	getOffsetRecursive = func(st *btf.Struct, fieldName string, baseOffset uint32) (int32, bool) {
		for _, m := range st.Members {
			memberOffset := baseOffset + uint32(m.Offset/8)

			// Direct match
			if m.Name == fieldName {
				return int32(memberOffset), true
			}

			// Anonymous member - recurse into it
			if m.Name == "" {
				// Resolve the type
				innerType := m.Type
				// Unwrap typedef if needed
				for {
					if td, ok := innerType.(*btf.Typedef); ok {
						innerType = td.Type
					} else {
						break
					}
				}
				// Check if it's a struct or union
				switch t := innerType.(type) {
				case *btf.Struct:
					if offset, found := getOffsetRecursive(t, fieldName, memberOffset); found {
						return offset, true
					}
				case *btf.Union:
					// For unions, all members start at the same offset
					for _, um := range t.Members {
						if um.Name == fieldName {
							return int32(memberOffset), true
						}
						// Check if union member is a struct containing the field
						umType := um.Type
						for {
							if td, ok := umType.(*btf.Typedef); ok {
								umType = td.Type
							} else {
								break
							}
						}
						if ust, ok := umType.(*btf.Struct); ok {
							if offset, found := getOffsetRecursive(ust, fieldName, memberOffset); found {
								return offset, true
							}
						}
					}
				}
			}
		}
		return 0, false
	}

	// Helper to get offset with recursive search
	getOffsetDeep := func(typeName, fieldName string) (int32, error) {
		var st *btf.Struct
		if err := spec.TypeByName(typeName, &st); err != nil {
			return 0, fmt.Errorf("type %s not found: %w", typeName, err)
		}

		if offset, found := getOffsetRecursive(st, fieldName, 0); found {
			return offset, nil
		}
		return 0, fmt.Errorf("field %s not found in %s", fieldName, typeName)
	}

	// task_struct->files
	if offset, err := getOffset("task_struct", "files"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.TaskFilesOffset = offset
	}

	// files_struct->fdt
	if offset, err := getOffset("files_struct", "fdt"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.FilesFdtOffset = offset
	}

	// fdtable->fd
	if offset, err := getOffset("fdtable", "fd"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.FdtFdOffset = offset
	}

	// fdtable->max_fds
	if offset, err := getOffset("fdtable", "max_fds"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.FdtMaxFdsOffset = offset
	}

	// file->private_data
	if offset, err := getOffset("file", "private_data"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.FilePrivateDataOffset = offset
	}

	// socket->sk
	if offset, err := getOffset("socket", "sk"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.SocketSkOffset = offset
	}

	// sock_common offsets - use deep search for anonymous union members
	// sock_common->skc_family
	if offset, err := getOffsetDeep("sock_common", "skc_family"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.SkFamilyOffset = offset
	}

	// sock_common->skc_daddr (inside anonymous union)
	if offset, err := getOffsetDeep("sock_common", "skc_daddr"); err != nil {
		klog.Warningf("BTF: %v, using fallback offset 0", err)
		// Fallback: skc_daddr is typically at offset 0 in sock_common
		offsets.SkDaddrOffset = 0
	} else {
		offsets.SkDaddrOffset = offset
	}

	// sock_common->skc_rcv_saddr (inside anonymous union, 4 bytes after skc_daddr)
	if offset, err := getOffsetDeep("sock_common", "skc_rcv_saddr"); err != nil {
		klog.Warningf("BTF: %v, using fallback offset 4", err)
		// Fallback: skc_rcv_saddr is typically at offset 4 in sock_common
		offsets.SkRcvSaddrOffset = 4
	} else {
		offsets.SkRcvSaddrOffset = offset
	}

	// sock_common->skc_dport (inside anonymous union)
	if offset, err := getOffsetDeep("sock_common", "skc_dport"); err != nil {
		klog.Warningf("BTF: %v, using fallback offset 12", err)
		// Fallback: skc_dport is typically at offset 12 in sock_common
		offsets.SkDportOffset = 12
	} else {
		offsets.SkDportOffset = offset
	}

	// sock_common->skc_num (inside anonymous union, 2 bytes after skc_dport)
	if offset, err := getOffsetDeep("sock_common", "skc_num"); err != nil {
		klog.Warningf("BTF: %v, using fallback offset 14", err)
		// Fallback: skc_num is typically at offset 14 in sock_common
		offsets.SkNumOffset = 14
	} else {
		offsets.SkNumOffset = offset
	}

	// sock_common->skc_v6_daddr
	if offset, err := getOffsetDeep("sock_common", "skc_v6_daddr"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.SkV6DaddrOffset = offset
	}

	// sock_common->skc_v6_rcv_saddr
	if offset, err := getOffsetDeep("sock_common", "skc_v6_rcv_saddr"); err != nil {
		klog.Warningf("BTF: %v", err)
	} else {
		offsets.SkV6RcvSaddrOffset = offset
	}

	// Mark as valid - we have fallbacks for essential offsets
	if offsets.TaskFilesOffset > 0 && offsets.FilesFdtOffset > 0 &&
		offsets.FdtFdOffset >= 0 && offsets.FilePrivateDataOffset > 0 &&
		offsets.SocketSkOffset >= 0 {
		offsets.OffsetsValid = 1
		klog.Infof("BTF socket offsets discovered: task->files=%d, files->fdt=%d, fdt->fd=%d, file->private_data=%d, socket->sk=%d, sk->daddr=%d, sk->rcv_saddr=%d, sk->dport=%d, sk->num=%d",
			offsets.TaskFilesOffset, offsets.FilesFdtOffset, offsets.FdtFdOffset,
			offsets.FilePrivateDataOffset, offsets.SocketSkOffset,
			offsets.SkDaddrOffset, offsets.SkRcvSaddrOffset, offsets.SkDportOffset, offsets.SkNumOffset)
	} else {
		klog.Warning("BTF socket offsets incomplete, socket info extraction may not work")
	}

	return offsets, nil
}

// initSocketInfoOffsets discovers offsets and writes them to the eBPF map
func (t *Tracer) initSocketInfoOffsets() error {
	// Find the map
	m, ok := t.collection.Maps["socket_info_offsets_map"]
	if !ok {
		klog.Warning("socket_info_offsets_map not found in eBPF collection, socket info extraction disabled")
		return nil
	}

	// Discover offsets using BTF
	offsets, err := discoverSocketOffsets()
	if err != nil {
		klog.Warningf("Failed to discover socket offsets: %v", err)
		return nil // Not fatal, just means socket info extraction won't work
	}

	// Write offsets to map
	key := uint32(0)
	if err := m.Update(key, offsets, ebpf.UpdateAny); err != nil {
		klog.Warningf("Failed to update socket_info_offsets_map: %v", err)
		return nil
	}

	klog.Info("Socket info offsets initialized successfully")
	return nil
}

// Helper to extract IP from socket info
func extractIPFromSocketInfo(addr [16]byte, family uint16) string {
	if family == 2 { // AF_INET
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	} else if family == 10 { // AF_INET6
		// Check for IPv4-mapped IPv6 address (::ffff:x.x.x.x)
		if addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
			addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
			addr[8] == 0 && addr[9] == 0 && addr[10] == 0xff && addr[11] == 0xff {
			return fmt.Sprintf("%d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
		}
		// Full IPv6
		return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
			addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15])
	}
	return ""
}

// SocketInfo represents extracted socket connection info
type SocketInfo struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Family  uint16
	Valid   bool
}

// GetSocketInfoFromL7Event extracts socket info from an L7 event
func GetSocketInfoFromL7Event(e *l7Event) *SocketInfo {
	if e.SocketInfoValid == 0 {
		return nil
	}
	return &SocketInfo{
		SrcIP:   extractIPFromSocketInfo(e.Saddr, e.AddrFamily),
		DstIP:   extractIPFromSocketInfo(e.Daddr, e.AddrFamily),
		SrcPort: e.Sport,
		DstPort: e.Dport,
		Family:  e.AddrFamily,
		Valid:   true,
	}
}

// Ensure binary encoding works correctly
var _ = binary.LittleEndian
