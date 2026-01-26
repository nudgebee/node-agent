package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"inet.af/netaddr"
)

func parseL7Event(data []byte) (Event, error) {
	if len(data) < 56 {
		return Event{}, fmt.Errorf("buffer too short for l7 event header: %d", len(data))
	}

	fd := binary.LittleEndian.Uint64(data[0:8])
	timestamp := binary.LittleEndian.Uint64(data[8:16])
	pid := binary.LittleEndian.Uint32(data[16:20])
	status := int32(binary.LittleEndian.Uint32(data[20:24]))
	duration := binary.LittleEndian.Uint64(data[24:32])
	protocol := data[32]
	method := data[33]
	// padding 2 bytes
	statementId := binary.LittleEndian.Uint32(data[36:40])
	payloadSize := binary.LittleEndian.Uint64(data[40:48])
	responseSize := binary.LittleEndian.Uint64(data[48:56])

	const maxPayloadSize = 4096

	// Payload is at offset 56
	pSize := int(payloadSize)
	if pSize > maxPayloadSize {
		pSize = maxPayloadSize
	}

	payloadOffset := 56
	if len(data) < payloadOffset+pSize {
		return Event{}, fmt.Errorf("buffer too short for l7 payload: %d", len(data))
	}
	payload := make([]byte, pSize)
	copy(payload, data[payloadOffset:payloadOffset+pSize])

	// Response is at offset 56 + 4096
	rSize := int(responseSize)
	if rSize > maxPayloadSize {
		rSize = maxPayloadSize
	}

	responseOffset := 56 + maxPayloadSize
	if len(data) < responseOffset+rSize {
		// It is possible the buffer is truncated if BPF program didn't send full struct?
		// But usually it sends fixed size.
		// If data is smaller, we truncate or error?
		// For safety, let's limit rSize to available data
		if len(data) > responseOffset {
			rSize = len(data) - responseOffset
		} else {
			rSize = 0
		}
	}
	response := make([]byte, rSize)
	if rSize > 0 {
		copy(response, data[responseOffset:responseOffset+rSize])
	}

	req := &l7.RequestData{
		Protocol:     l7.Protocol(protocol),
		Status:       l7.Status(status),
		Duration:     time.Duration(duration),
		Method:       l7.Method(method),
		StatementId:  statementId,
		PayloadSize:  payloadSize,
		ResponseSize: responseSize,
		Payload:      payload,
		Response:     response,
	}

	return Event{
		Type:      EventTypeL7Request,
		Pid:       pid,
		Fd:        fd,
		Timestamp: timestamp,
		L7Request: req,
	}, nil
}

func parseTcpEvent(data []byte) (Event, error) {
	// TCP event size check
	// Fd(8)+Ts(8)+Dur(8)+Type(4)+Pid(4)+Sent(8)+Recv(8)+SPort(2)+DPort(2)+APort(2) = 54
	// SAddr(16) + DAddr(16) + AAddr(16) = 48
	// Total 102 bytes.
	if len(data) < 102 {
		return Event{}, fmt.Errorf("buffer too short for tcp event: %d", len(data))
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

func parseFileEvent(data []byte) (Event, error) {
	// Type(4)+Pid(4)+Fd(8)+Mnt(8)+Log(8) = 32 bytes
	// The struct in tracer.go uses Log uint64, but checks > 0.
	if len(data) < 32 {
		return Event{}, fmt.Errorf("buffer too short for file event: %d", len(data))
	}

	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	fd := binary.LittleEndian.Uint64(data[8:16])
	mnt := binary.LittleEndian.Uint64(data[16:24])
	logVal := binary.LittleEndian.Uint64(data[24:32])

	return Event{Type: typ, Pid: pid, Fd: fd, Mnt: mnt, Log: logVal > 0}, nil
}

func parseProcEvent(data []byte) (Event, error) {
	// Type(4)+Pid(4)+Reason(4) = 12 bytes
	if len(data) < 12 {
		return Event{}, fmt.Errorf("buffer too short for proc event: %d", len(data))
	}

	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	reason := binary.LittleEndian.Uint32(data[8:12])

	return Event{Type: typ, Reason: EventReason(reason), Pid: pid}, nil
}

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}
