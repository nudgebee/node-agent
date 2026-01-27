package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

// Original struct definitions for testing (renamed to avoid conflict)
type l7EventTest struct {
	Fd                  uint64
	ConnectionTimestamp uint64
	Pid                 uint32
	Status              int32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	StatementId         uint32
	PayloadSize         uint64
	ResponseSize        uint64
	Payload             [4096]byte
	Response            [4096]byte
}

type tcpEventTest struct {
	Fd            uint64
	Timestamp     uint64
	Duration      uint64
	Type          EventType
	Pid           uint32
	BytesSent     uint64
	BytesReceived uint64
	SPort         uint16
	DPort         uint16
	Aport         uint16
	SAddr         [16]byte
	DAddr         [16]byte
	AAddr         [16]byte
}

type fileEventTest struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type procEventTest struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

func TestParseL7Event(t *testing.T) {
	expectedPayload := []byte("request payload")
	expectedResponse := []byte("response payload")

	v := &l7EventTest{
		Fd:                  12345,
		ConnectionTimestamp: 67890,
		Pid:                 111,
		Status:              200,
		Duration:            500,
		Protocol:            uint8(l7.ProtocolHTTP),
		Method:              1, // Arbitrary method
		StatementId:         999,
		PayloadSize:         uint64(len(expectedPayload)),
		ResponseSize:        uint64(len(expectedResponse)),
	}
	copy(v.Payload[:], expectedPayload)
	copy(v.Response[:], expectedResponse)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	assert.NoError(t, err)

	data := buf.Bytes()

	// Test new parsing
	event, err := parseL7Event(data)
	assert.NoError(t, err)

	assert.Equal(t, EventTypeL7Request, event.Type)
	assert.Equal(t, v.Fd, event.Fd)
	assert.Equal(t, v.ConnectionTimestamp, event.Timestamp)
	assert.Equal(t, v.Pid, event.Pid)

	req := event.L7Request
	assert.Equal(t, l7.ProtocolHTTP, req.Protocol)
	assert.Equal(t, l7.Status(200), req.Status)
	assert.Equal(t, time.Duration(500), req.Duration)
	assert.Equal(t, l7.Method(1), req.Method)
	assert.Equal(t, v.StatementId, req.StatementId)
	assert.Equal(t, v.PayloadSize, req.PayloadSize)
	assert.Equal(t, v.ResponseSize, req.ResponseSize)
	assert.Equal(t, expectedPayload, req.Payload)
	assert.Equal(t, expectedResponse, req.Response)
}

func TestParseTCPEvent(t *testing.T) {
	sAddr := [16]byte{192, 168, 1, 1} // Rest are 0
	dAddr := [16]byte{10, 0, 0, 1}

	v := &tcpEventTest{
		Fd:            555,
		Timestamp:     123456789,
		Duration:      100,
		Type:          EventTypeConnectionClose,
		Pid:           777,
		BytesSent:     1000,
		BytesReceived: 2000,
		SPort:         1234,
		DPort:         80,
		Aport:         5678,
		SAddr:         sAddr,
		DAddr:         dAddr,
		AAddr:         sAddr,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	assert.NoError(t, err)

	data := buf.Bytes()

	event, err := parseTCPEvent(data)
	assert.NoError(t, err)

	assert.Equal(t, EventTypeConnectionClose, event.Type)
	assert.Equal(t, v.Fd, event.Fd)
	assert.Equal(t, v.Timestamp, event.Timestamp)
	assert.Equal(t, time.Duration(100), event.Duration)
	assert.Equal(t, v.Pid, event.Pid)

	assert.NotNil(t, event.TrafficStats)
	assert.Equal(t, v.BytesSent, event.TrafficStats.BytesSent)
	assert.Equal(t, v.BytesReceived, event.TrafficStats.BytesReceived)

	// Verify IPs
	i, _ := netaddr.FromStdIP(sAddr[:])
	expectedSrc := netaddr.IPPortFrom(i, v.SPort)
	assert.Equal(t, expectedSrc, event.SrcAddr)
}

func TestParseFileEvent(t *testing.T) {
	v := &fileEventTest{
		Type: EventTypeFileOpen,
		Pid:  888,
		Fd:   999,
		Mnt:  10,
		Log:  1,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	assert.NoError(t, err)

	data := buf.Bytes()

	event, err := parseFileEvent(data)
	assert.NoError(t, err)

	assert.Equal(t, EventTypeFileOpen, event.Type)
	assert.Equal(t, v.Pid, event.Pid)
	assert.Equal(t, v.Fd, event.Fd)
	assert.Equal(t, v.Mnt, event.Mnt)
	assert.True(t, event.Log)
}

func TestParseProcEvent(t *testing.T) {
	v := &procEventTest{
		Type:   EventTypeProcessStart,
		Pid:    123,
		Reason: uint32(EventReasonOOMKill),
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, v)
	assert.NoError(t, err)

	data := buf.Bytes()

	event, err := parseProcEvent(data)
	assert.NoError(t, err)

	assert.Equal(t, EventTypeProcessStart, event.Type)
	assert.Equal(t, v.Pid, event.Pid)
	assert.Equal(t, EventReasonOOMKill, event.Reason)
}
