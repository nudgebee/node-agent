package ebpftracer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"inet.af/netaddr"
)

func ipPort(ip [16]byte, port uint16) netaddr.IPPort {
	i, _ := netaddr.FromStdIP(ip[:])
	return netaddr.IPPortFrom(i, port)
}

func parseL7Event(data []byte) (*Event, error) {
	if len(data) < 56 {
		return nil, fmt.Errorf("buffer too small for l7_event header: %d", len(data))
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

	var payload []byte
	if payloadSize > 0 {
		start := 56
		end := start + int(payloadSize)
		if end > len(data) {
			end = len(data)
		}
		if start < end {
			payload = make([]byte, end-start)
			copy(payload, data[start:end])
		}
	}

	var response []byte
	if responseSize > 0 {
		start := 56 + 4096
		end := start + int(responseSize)
		if end > len(data) {
			end = len(data)
		}
		if start < end {
			response = make([]byte, end-start)
			copy(response, data[start:end])
		}
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

	return &Event{
		Type:      EventTypeL7Request,
		Pid:       pid,
		Fd:        fd,
		Timestamp: connectionTimestamp,
		L7Request: req,
	}, nil
}

func parseTCPEvent(data []byte) (*Event, error) {
	if len(data) < 102 {
		return nil, fmt.Errorf("buffer too small for tcp_event: %d", len(data))
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

	event := &Event{
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

func parseFileEvent(data []byte) (*Event, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("buffer too small for file_event: %d", len(data))
	}
	// struct file_event {
	// 	__u32 type;
	// 	__u32 pid;
	// 	__u64 fd;
	// 	__u64 mnt;
	// 	__u64 log;
	// };
	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	fd := binary.LittleEndian.Uint64(data[8:16])
	mnt := binary.LittleEndian.Uint64(data[16:24])
	log := binary.LittleEndian.Uint64(data[24:32])

	return &Event{Type: typ, Pid: pid, Fd: fd, Mnt: mnt, Log: log > 0}, nil
}

func parseProcEvent(data []byte) (*Event, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("buffer too small for proc_event: %d", len(data))
	}
	// struct proc_event {
	//     __u32 type;
	//     __u32 pid;
	//     __u32 reason;
	// };
	typ := EventType(binary.LittleEndian.Uint32(data[0:4]))
	pid := binary.LittleEndian.Uint32(data[4:8])
	reason := EventReason(binary.LittleEndian.Uint32(data[8:12]))

	return &Event{Type: typ, Reason: reason, Pid: pid}, nil
}
