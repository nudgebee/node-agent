package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"inet.af/netaddr"
)

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	return netaddr.IPPortFrom(netaddr.IPFrom16(ip), port)
}

func parseL7Event(data []byte) (Event, error) {
	if len(data) < 56 {
		return Event{}, fmt.Errorf("buffer too short for l7Event: %d", len(data))
	}

	fd := binary.LittleEndian.Uint64(data[0:8])
	timestamp := binary.LittleEndian.Uint64(data[8:16])
	pid := binary.LittleEndian.Uint32(data[16:20])
	status := int32(binary.LittleEndian.Uint32(data[20:24]))
	duration := binary.LittleEndian.Uint64(data[24:32])
	protocol := data[32]
	method := data[33]
	// padding 2 bytes at 34
	statementId := binary.LittleEndian.Uint32(data[36:40])
	payloadSize := binary.LittleEndian.Uint64(data[40:48])
	responseSize := binary.LittleEndian.Uint64(data[48:56])

	// Payload starts at 56
	// The struct defines Payload [4096]byte and Response [4096]byte
	// Total size of payload+response area is 8192 bytes.
	// We need to extract payload and response based on payloadSize and responseSize.

	// Bounds check for the rest of the data isn't strictly necessary if we cap at len(data),
	// but eBPF should send enough data.
	// However, we only care about the actual payload/response bytes.

	offset := 56
	if len(data) < offset {
		return Event{}, fmt.Errorf("buffer too short for l7Event payload: %d", len(data))
	}

	// Payload
	pSize := int(payloadSize)
	// The Payload field is 4096 bytes long in the struct.
	// So Response starts at 56 + 4096.
	responseOffset := 56 + 4096

	var payloadData []byte
	if pSize > 0 {
		// Cap pSize to 4096 (max payload size) just in case
		if pSize > 4096 {
			pSize = 4096
		}
		// Also cap to available data in the payload window
		available := len(data) - offset
		if available > 4096 {
			available = 4096
		}
		if pSize > available {
			pSize = available
		}

		payloadData = make([]byte, pSize)
		copy(payloadData, data[offset:offset+pSize])
	}

	// Response
	rSize := int(responseSize)
	var responseData []byte

	if len(data) >= responseOffset && rSize > 0 {
		if rSize > 4096 {
			rSize = 4096
		}
		available := len(data) - responseOffset
		if available > 4096 {
			available = 4096
		}
		if rSize > available {
			rSize = available
		}

		responseData = make([]byte, rSize)
		copy(responseData, data[responseOffset:responseOffset+rSize])
	}

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

	return Event{
		Type:      EventTypeL7Request,
		Pid:       pid,
		Fd:        fd,
		Timestamp: timestamp,
		L7Request: req,
	}, nil
}

func parseFileEvent(data []byte) (Event, error) {
	if len(data) < 32 {
		return Event{}, fmt.Errorf("buffer too short for fileEvent: %d", len(data))
	}
	// type (4), pid (4), fd (8), mnt (8), log (8)
	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	fd := binary.LittleEndian.Uint64(data[8:16])
	mnt := binary.LittleEndian.Uint64(data[16:24])
	logVal := binary.LittleEndian.Uint64(data[24:32])

	return Event{
		Type: typ,
		Pid:  pid,
		Fd:   fd,
		Mnt:  mnt,
		Log:  logVal > 0,
	}, nil
}

func parseProcEvent(data []byte) (Event, error) {
	if len(data) < 12 {
		return Event{}, fmt.Errorf("buffer too short for procEvent: %d", len(data))
	}
	// type (4), pid (4), reason (4)
	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	reason := binary.LittleEndian.Uint32(data[8:12])

	return Event{
		Type:   typ,
		Reason: EventReason(reason),
		Pid:    pid,
	}, nil
}

func parseTCPEvent(data []byte) (Event, error) {
	if len(data) < 102 {
		return Event{}, fmt.Errorf("buffer too short for tcpEvent: %d", len(data))
	}

	fd := binary.LittleEndian.Uint64(data[0:8])
	timestamp := binary.LittleEndian.Uint64(data[8:16])
	duration := binary.LittleEndian.Uint64(data[16:24])
	typ := EventType(binary.LittleEndian.Uint32(data[24:28]))
	pid := binary.LittleEndian.Uint32(data[28:32])
	bytesSent := binary.LittleEndian.Uint64(data[32:40])
	bytesReceived := binary.LittleEndian.Uint64(data[40:48])
	sPort := binary.LittleEndian.Uint16(data[48:50])
	dPort := binary.LittleEndian.Uint16(data[50:52])
	aPort := binary.LittleEndian.Uint16(data[52:54])

	var sAddr [16]byte
	copy(sAddr[:], data[54:70])

	var dAddr [16]byte
	copy(dAddr[:], data[70:86])

	var aAddr [16]byte
	copy(aAddr[:], data[86:102])

	event := Event{
		Type:          typ,
		Pid:           pid,
		SrcAddr:       ipPort(sAddr, sPort),
		DstAddr:       ipPort(dAddr, dPort),
		ActualDstAddr: ipPort(aAddr, aPort),
		Fd:            fd,
		Timestamp:     timestamp,
		Duration:      time.Duration(duration),
	}

	if typ == EventTypeConnectionClose {
		event.TrafficStats = &TrafficStats{
			BytesSent:     bytesSent,
			BytesReceived: bytesReceived,
		}
	}

	return event, nil
}
