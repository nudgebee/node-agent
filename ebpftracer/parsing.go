package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
)

func parseL7Event(data []byte) (Event, error) {
	if len(data) < 8248 { // Size of l7Event struct
		return Event{}, fmt.Errorf("buffer too short for l7Event: %d", len(data))
	}

	fd := binary.LittleEndian.Uint64(data[0:8])
	connectionTimestamp := binary.LittleEndian.Uint64(data[8:16])
	pid := binary.LittleEndian.Uint32(data[16:20])
	status := int32(binary.LittleEndian.Uint32(data[20:24]))
	duration := binary.LittleEndian.Uint64(data[24:32])
	protocol := data[32]
	method := data[33]
	// padding 34-36
	statementId := binary.LittleEndian.Uint32(data[36:40])
	payloadSize := binary.LittleEndian.Uint64(data[40:48])
	responseSize := binary.LittleEndian.Uint64(data[48:56])

	// Cap sizes to 4096 as per struct definition
	if payloadSize > 4096 {
		payloadSize = 4096
	}
	if responseSize > 4096 {
		responseSize = 4096
	}

	payloadData := make([]byte, payloadSize)
	copy(payloadData, data[56:56+payloadSize])

	responseData := make([]byte, responseSize)
	copy(responseData, data[4152:4152+responseSize])

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
		Timestamp: connectionTimestamp,
		L7Request: req,
	}, nil
}

func parseTCPEvent(data []byte) (Event, error) {
	if len(data) < 102 { // Size of tcpEvent struct
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

	var sAddr, dAddr, aAddr [16]byte
	copy(sAddr[:], data[54:70])
	copy(dAddr[:], data[70:86])
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
	if len(data) < 32 { // Size of fileEvent struct
		return Event{}, fmt.Errorf("buffer too short for fileEvent: %d", len(data))
	}

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
	if len(data) < 12 { // Size of procEvent struct
		return Event{}, fmt.Errorf("buffer too short for procEvent: %d", len(data))
	}

	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	reason := binary.LittleEndian.Uint32(data[8:12])

	return Event{
		Type:   typ,
		Reason: EventReason(reason),
		Pid:    pid,
	}, nil
}
