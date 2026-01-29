package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"inet.af/netaddr"
)

func parseL7Event(data []byte) (*Event, error) {
	if len(data) < 8248 { // Size of l7Event struct
		return nil, fmt.Errorf("buffer too short for l7Event: %d", len(data))
	}

	// Manual parsing of l7Event
	// type l7Event struct {
	// 	Fd                  uint64     // 0
	// 	ConnectionTimestamp uint64     // 8
	// 	Pid                 uint32     // 16
	// 	Status              int32      // 20
	// 	Duration            uint64     // 24
	// 	Protocol            uint8      // 32
	// 	Method              uint8      // 33
	// 	Padding             uint16     // 34
	// 	StatementId         uint32     // 36
	// 	PayloadSize         uint64     // 40
	// 	ResponseSize        uint64     // 48
	// 	Payload             [4096]byte // 56
	// 	Response            [4096]byte // 4152
	// }                           // Total: 8248

	fd := binary.LittleEndian.Uint64(data[0:8])
	connectionTimestamp := binary.LittleEndian.Uint64(data[8:16])
	pid := binary.LittleEndian.Uint32(data[16:20])
	status := int32(binary.LittleEndian.Uint32(data[20:24]))
	duration := binary.LittleEndian.Uint64(data[24:32])
	protocol := data[32]
	method := data[33]
	// padding skipped
	statementId := binary.LittleEndian.Uint32(data[36:40])
	payloadSize := binary.LittleEndian.Uint64(data[40:48])
	responseSize := binary.LittleEndian.Uint64(data[48:56])

	pSize := int(payloadSize)
	if pSize > 4096 {
		pSize = 4096
	}
	// Payload starts at 56
	payloadData := make([]byte, pSize)
	copy(payloadData, data[56:56+pSize])

	rSize := int(responseSize)
	if rSize > 4096 {
		rSize = 4096
	}
	// Response starts at 56 + 4096 = 4152
	responseData := make([]byte, rSize)
	copy(responseData, data[4152:4152+rSize])

	req := &l7.RequestData{
		Protocol:     l7.Protocol(protocol),
		Status:       l7.Status(status),
		Duration:     time.Duration(duration),
		Method:       l7.Method(method),
		StatementId:  statementId,
		PayloadSize:  payloadSize,
		ResponseSize: responseSize,
		Payload:      payloadData,
		Response:     responseData,
	}

	return &Event{
		Type:      EventTypeL7Request,
		Pid:       pid,
		Fd:        fd,
		Timestamp: connectionTimestamp,
		L7Request: req,
	}, nil
}

func parseTcpEvent(data []byte) (*Event, error) {
	if len(data) < 102 {
		return nil, fmt.Errorf("buffer too short for tcpEvent: %d", len(data))
	}
	// type tcpEvent struct {
	// 	Fd            uint64   // 0
	// 	Timestamp     uint64   // 8
	// 	Duration      uint64   // 16
	// 	Type          EventType // 24 (uint32)
	// 	Pid           uint32   // 28
	// 	BytesSent     uint64   // 32
	// 	BytesReceived uint64   // 40
	// 	SPort         uint16   // 48
	// 	DPort         uint16   // 50
	// 	Aport         uint16   // 52
	// 	SAddr         [16]byte // 54
	// 	DAddr         [16]byte // 70
	// 	AAddr         [16]byte // 86
	// }

	typ := EventType(binary.LittleEndian.Uint32(data[24:28]))
	pid := binary.LittleEndian.Uint32(data[28:32])
	sPort := binary.LittleEndian.Uint16(data[48:50])
	dPort := binary.LittleEndian.Uint16(data[50:52])
	aPort := binary.LittleEndian.Uint16(data[52:54])

	var sAddr, dAddr, aAddr [16]byte
	copy(sAddr[:], data[54:70])
	copy(dAddr[:], data[70:86])
	copy(aAddr[:], data[86:102])

	event := &Event{
		Type:          typ,
		Pid:           pid,
		SrcAddr:       ipPort(sAddr, sPort),
		DstAddr:       ipPort(dAddr, dPort),
		ActualDstAddr: ipPort(aAddr, aPort),
		Fd:            binary.LittleEndian.Uint64(data[0:8]),
		Timestamp:     binary.LittleEndian.Uint64(data[8:16]),
		Duration:      time.Duration(binary.LittleEndian.Uint64(data[16:24])),
	}

	if typ == EventTypeConnectionClose {
		event.TrafficStats = &TrafficStats{
			BytesSent:     binary.LittleEndian.Uint64(data[32:40]),
			BytesReceived: binary.LittleEndian.Uint64(data[40:48]),
		}
	}

	return event, nil
}

func parseFileEvent(data []byte) (*Event, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("buffer too short for fileEvent: %d", len(data))
	}
	// type fileEvent struct {
	// 	Type EventType // 0 (uint32)
	// 	Pid  uint32    // 4
	// 	Fd   uint64    // 8
	// 	Mnt  uint64    // 16
	// 	Log  uint64    // 24
	// }

	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	fd := binary.LittleEndian.Uint64(data[8:16])
	mnt := binary.LittleEndian.Uint64(data[16:24])
	logVal := binary.LittleEndian.Uint64(data[24:32])

	return &Event{
		Type: typ,
		Pid:  pid,
		Fd:   fd,
		Mnt:  mnt,
		Log:  logVal > 0,
	}, nil
}

func parseProcEvent(data []byte) (*Event, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("buffer too short for procEvent: %d", len(data))
	}
	// type procEvent struct {
	// 	Type   EventType // 0 (uint32)
	// 	Pid    uint32    // 4
	// 	Reason uint32    // 8
	// }

	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	reason := binary.LittleEndian.Uint32(data[8:12])

	return &Event{
		Type:   typ,
		Pid:    pid,
		Reason: EventReason(reason),
	}, nil
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}
