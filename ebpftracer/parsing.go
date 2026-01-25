package ebpftracer

import (
	"encoding/binary"
)

func parseL7Event(data []byte, v *l7Event) bool {
	if len(data) < 56 {
		return false
	}
	v.Fd = binary.LittleEndian.Uint64(data[0:8])
	v.ConnectionTimestamp = binary.LittleEndian.Uint64(data[8:16])
	v.Pid = binary.LittleEndian.Uint32(data[16:20])
	v.Status = int32(binary.LittleEndian.Uint32(data[20:24]))
	v.Duration = binary.LittleEndian.Uint64(data[24:32])
	v.Protocol = data[32]
	v.Method = data[33]
	v.Padding = binary.LittleEndian.Uint16(data[34:36])
	v.StatementId = binary.LittleEndian.Uint32(data[36:40])
	v.PayloadSize = binary.LittleEndian.Uint64(data[40:48])
	v.ResponseSize = binary.LittleEndian.Uint64(data[48:56])
	// Payload and Response arrays are intentionally not copied here for performance.
	// They should be extracted directly from data using offsets 56 and 4152.
	return true
}

func parseTCPEvent(data []byte, v *tcpEvent) bool {
	if len(data) < 104 {
		return false
	}
	v.Fd = binary.LittleEndian.Uint64(data[0:8])
	v.Timestamp = binary.LittleEndian.Uint64(data[8:16])
	v.Duration = binary.LittleEndian.Uint64(data[16:24])
	v.Type = EventType(binary.LittleEndian.Uint32(data[24:28]))
	v.Pid = binary.LittleEndian.Uint32(data[28:32])
	v.BytesSent = binary.LittleEndian.Uint64(data[32:40])
	v.BytesReceived = binary.LittleEndian.Uint64(data[40:48])
	v.SPort = binary.LittleEndian.Uint16(data[48:50])
	v.DPort = binary.LittleEndian.Uint16(data[50:52])
	v.Aport = binary.LittleEndian.Uint16(data[52:54])
	copy(v.SAddr[:], data[54:70])
	copy(v.DAddr[:], data[70:86])
	copy(v.AAddr[:], data[86:102])
	return true
}

func parseFileEvent(data []byte, v *fileEvent) bool {
	if len(data) < 32 {
		return false
	}
	v.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	v.Pid = binary.LittleEndian.Uint32(data[4:8])
	v.Fd = binary.LittleEndian.Uint64(data[8:16])
	v.Mnt = binary.LittleEndian.Uint64(data[16:24])
	v.Log = binary.LittleEndian.Uint64(data[24:32])
	return true
}

func parseProcEvent(data []byte, v *procEvent) bool {
	if len(data) < 12 {
		return false
	}
	v.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	v.Pid = binary.LittleEndian.Uint32(data[4:8])
	v.Reason = uint32(binary.LittleEndian.Uint32(data[8:12]))
	return true
}
