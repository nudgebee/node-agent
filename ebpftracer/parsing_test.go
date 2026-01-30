package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Structs for generating test data (matching original definitions)
type testL7Event struct {
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

type testTcpEvent struct {
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

type testFileEvent struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type testProcEvent struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

func TestParseL7Event(t *testing.T) {
	payload := []byte("SELECT * FROM users")
	response := []byte("OK")

	v := testL7Event{
		Fd:                  12345,
		ConnectionTimestamp: 99999,
		Pid:                 1001,
		Status:              200,
		Duration:            500000,
		Protocol:            1,
		Method:              2,
		StatementId:         42,
		PayloadSize:         uint64(len(payload)),
		ResponseSize:        uint64(len(response)),
	}
	copy(v.Payload[:], payload)
	copy(v.Response[:], response)

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &v)
	assert.NoError(t, err)

	event, err := parseL7Event(buf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, EventTypeL7Request, event.Type)
	assert.Equal(t, uint32(1001), event.Pid)
	assert.Equal(t, uint64(12345), event.Fd)
	assert.Equal(t, uint64(99999), event.Timestamp)
	assert.NotNil(t, event.L7Request)
	assert.Equal(t, payload, event.L7Request.Payload)
	assert.Equal(t, response, event.L7Request.Response)
	assert.Equal(t, time.Duration(500000), event.L7Request.Duration)
}

func TestParseTCPEvent(t *testing.T) {
	v := testTcpEvent{
		Fd:            555,
		Timestamp:     8888,
		Duration:      123,
		Type:          EventTypeConnectionClose,
		Pid:           202,
		BytesSent:     100,
		BytesReceived: 200,
		SPort:         80,
		DPort:         12345,
		Aport:         54321,
	}
	// 10.0.0.1
	copy(v.SAddr[:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1})

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &v)
	assert.NoError(t, err)

	// Verify buffer size is 102
	assert.Equal(t, 102, buf.Len())

	event, err := parseTCPEvent(buf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, EventTypeConnectionClose, event.Type)
	assert.Equal(t, uint32(202), event.Pid)
	assert.Equal(t, uint64(555), event.Fd)
	assert.Equal(t, "10.0.0.1:80", event.SrcAddr.String())
	assert.Equal(t, uint64(100), event.TrafficStats.BytesSent)
	assert.Equal(t, uint64(200), event.TrafficStats.BytesReceived)
}

func TestParseFileEvent(t *testing.T) {
	v := testFileEvent{
		Type: EventTypeFileOpen,
		Pid:  303,
		Fd:   777,
		Mnt:  888,
		Log:  1,
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &v)
	assert.NoError(t, err)

	event, err := parseFileEvent(buf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, EventTypeFileOpen, event.Type)
	assert.Equal(t, uint32(303), event.Pid)
	assert.Equal(t, uint64(777), event.Fd)
	assert.True(t, event.Log)
}

func TestParseProcEvent(t *testing.T) {
	v := testProcEvent{
		Type:   EventTypeProcessExit,
		Pid:    404,
		Reason: uint32(EventReasonOOMKill),
	}
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &v)
	assert.NoError(t, err)

	event, err := parseProcEvent(buf.Bytes())
	assert.NoError(t, err)

	assert.Equal(t, EventTypeProcessExit, event.Type)
	assert.Equal(t, uint32(404), event.Pid)
	assert.Equal(t, EventReasonOOMKill, event.Reason)
}
