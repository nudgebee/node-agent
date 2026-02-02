package ebpftracer

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/coroot/coroot-node-agent/ebpftracer/l7"
	"github.com/stretchr/testify/assert"
)

func TestParseL7Event(t *testing.T) {
	// struct l7_event size is 8248
	data := make([]byte, 8248)

	// Fd = 123
	binary.LittleEndian.PutUint64(data[0:8], 123)
	// ConnectionTimestamp = 1000
	binary.LittleEndian.PutUint64(data[8:16], 1000)
	// Pid = 456
	binary.LittleEndian.PutUint32(data[16:20], 456)
	// Status = 200
	binary.LittleEndian.PutUint32(data[20:24], 200)
	// Duration = 50ms
	binary.LittleEndian.PutUint64(data[24:32], uint64(50*time.Millisecond))
	// Protocol = HTTP (1)
	data[32] = 1
	// Method = GET (1)
	data[33] = 1
	// StatementId = 789
	binary.LittleEndian.PutUint32(data[36:40], 789)
	// PayloadSize = 5
	binary.LittleEndian.PutUint64(data[40:48], 5)
	// ResponseSize = 3
	binary.LittleEndian.PutUint64(data[48:56], 3)

	// Payload "hello" at offset 56
	copy(data[56:], []byte("hello"))

	// Response "bye" at offset 56 + 4096 = 4152
	copy(data[4152:], []byte("bye"))

	event, err := parseL7Event(data)
	assert.NoError(t, err)
	assert.NotNil(t, event)
	assert.Equal(t, EventTypeL7Request, event.Type)
	assert.Equal(t, uint64(123), event.Fd)
	assert.Equal(t, uint64(1000), event.Timestamp)
	assert.Equal(t, uint32(456), event.Pid)

	req := event.L7Request
	assert.NotNil(t, req)
	assert.Equal(t, l7.Protocol(1), req.Protocol)
	assert.Equal(t, l7.Status(200), req.Status)
	assert.Equal(t, 50*time.Millisecond, req.Duration)
	assert.Equal(t, l7.Method(1), req.Method)
	assert.Equal(t, uint32(789), req.StatementId)
	assert.Equal(t, uint64(5), req.PayloadSize)
	assert.Equal(t, uint64(3), req.ResponseSize)
	assert.Equal(t, []byte("hello"), req.Payload)
	assert.Equal(t, []byte("bye"), req.Response)
}

func TestParseTCPEvent(t *testing.T) {
	data := make([]byte, 104) // 102 bytes data + padding
	// Fd = 1
	binary.LittleEndian.PutUint64(data[0:8], 1)
	// Timestamp
	binary.LittleEndian.PutUint64(data[8:16], 2000)
	// Type = EventTypeConnectionOpen (3)
	binary.LittleEndian.PutUint32(data[24:28], 3)
	// Pid = 2
	binary.LittleEndian.PutUint32(data[28:32], 2)
	// SPort = 80
	binary.LittleEndian.PutUint16(data[48:50], 80)
	// DPort = 443
	binary.LittleEndian.PutUint16(data[50:52], 443)

	// SAddr 127.0.0.1 (IPv4 mapped IPv6)
	// ::ffff:127.0.0.1
	sAddr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
	copy(data[54:70], sAddr[:])

	event, err := parseTCPEvent(data)
	assert.NoError(t, err)
	assert.Equal(t, EventTypeConnectionOpen, event.Type)
	assert.Equal(t, "127.0.0.1:80", event.SrcAddr.String())
}

func TestParseFileEvent(t *testing.T) {
	data := make([]byte, 32)
	// Type = EventTypeFileOpen (8)
	binary.LittleEndian.PutUint32(data[0:4], 8)
	// Pid = 10
	binary.LittleEndian.PutUint32(data[4:8], 10)
	// Fd = 5
	binary.LittleEndian.PutUint64(data[8:16], 5)

	event, err := parseFileEvent(data)
	assert.NoError(t, err)
	assert.Equal(t, EventTypeFileOpen, event.Type)
	assert.Equal(t, uint32(10), event.Pid)
	assert.Equal(t, uint64(5), event.Fd)
}

func TestParseProcEvent(t *testing.T) {
	data := make([]byte, 12)
	// Type = EventTypeProcessStart (1)
	binary.LittleEndian.PutUint32(data[0:4], 1)
	// Pid = 20
	binary.LittleEndian.PutUint32(data[4:8], 20)
	// Reason = EventReasonNone (0)

	event, err := parseProcEvent(data)
	assert.NoError(t, err)
	assert.Equal(t, EventTypeProcessStart, event.Type)
	assert.Equal(t, uint32(20), event.Pid)
}
