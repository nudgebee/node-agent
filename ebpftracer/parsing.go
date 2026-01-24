package ebpftracer

import (
	"encoding/binary"
	"fmt"
)

func parseL7Event(data []byte, v *l7Event) error {
	if len(data) < 56 {
		return fmt.Errorf("buffer too short for l7Event: %d < 56", len(data))
	}
	v.Fd = binary.LittleEndian.Uint64(data[0:8])
	v.ConnectionTimestamp = binary.LittleEndian.Uint64(data[8:16])
	v.Pid = binary.LittleEndian.Uint32(data[16:20])
	v.Status = int32(binary.LittleEndian.Uint32(data[20:24]))
	v.Duration = binary.LittleEndian.Uint64(data[24:32])
	v.Protocol = data[32]
	v.Method = data[33]
	// Padding 2 bytes at 34-36
	v.StatementId = binary.LittleEndian.Uint32(data[36:40])
	v.PayloadSize = binary.LittleEndian.Uint64(data[40:48])
	v.ResponseSize = binary.LittleEndian.Uint64(data[48:56])

	offset := 56
	pSize := int(v.PayloadSize)
	if pSize > len(v.Payload) {
		pSize = len(v.Payload)
	}
	if len(data) >= offset+pSize {
		copy(v.Payload[:pSize], data[offset:offset+pSize])
	}

	offset += 4096
	rSize := int(v.ResponseSize)
	if rSize > len(v.Response) {
		rSize = len(v.Response)
	}
	if len(data) >= offset+rSize {
		copy(v.Response[:rSize], data[offset:offset+rSize])
	}
	return nil
}

func parseTcpEvent(data []byte, v *tcpEvent) error {
	if len(data) < 102 {
		return fmt.Errorf("buffer too short for tcpEvent: %d < 102", len(data))
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
	return nil
}

func parseFileEvent(data []byte, v *fileEvent) error {
	if len(data) < 32 {
		return fmt.Errorf("buffer too short for fileEvent: %d < 32", len(data))
	}
	v.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	v.Pid = binary.LittleEndian.Uint32(data[4:8])
	v.Fd = binary.LittleEndian.Uint64(data[8:16])
	v.Mnt = binary.LittleEndian.Uint64(data[16:24])
	v.Log = binary.LittleEndian.Uint64(data[24:32])
	return nil
}

func parseProcEvent(data []byte, v *procEvent) error {
	if len(data) < 12 {
		return fmt.Errorf("buffer too short for procEvent: %d < 12", len(data))
	}
	v.Type = EventType(binary.LittleEndian.Uint32(data[0:4]))
	v.Pid = binary.LittleEndian.Uint32(data[4:8])
	v.Reason = binary.LittleEndian.Uint32(data[8:12])
	return nil
}
