package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Structs for generating test data (must match parsing logic expectations)
type l7EventStruct struct {
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

type tcpEventStruct struct {
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

type fileEventStruct struct {
	Type EventType
	Pid  uint32
	Fd   uint64
	Mnt  uint64
	Log  uint64
}

type procEventStruct struct {
	Type   EventType
	Pid    uint32
	Reason uint32
}

func TestParseL7Event(t *testing.T) {
	event := l7EventStruct{
		Fd:                  123,
		ConnectionTimestamp: 456,
		Pid:                 789,
		Status:              200,
		Duration:            1000,
		Protocol:            1,
		Method:              2,
		StatementId:         999,
		PayloadSize:         5,
		ResponseSize:        3,
		Payload:             [4096]byte{1, 2, 3, 4, 5},
		Response:            [4096]byte{6, 7, 8},
	}
	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, event))
	data := buf.Bytes()

	parsed, err := parseL7Event(data)
	require.NoError(t, err)

	assert.Equal(t, EventTypeL7Request, parsed.Type)
	assert.Equal(t, event.Fd, parsed.Fd)
	assert.Equal(t, event.ConnectionTimestamp, parsed.Timestamp)
	assert.Equal(t, event.Pid, parsed.Pid)
	assert.Equal(t, int(event.Status), int(parsed.L7Request.Status))
	assert.Equal(t, time.Duration(event.Duration), parsed.L7Request.Duration)
	assert.Equal(t, int(event.Protocol), int(parsed.L7Request.Protocol))
	assert.Equal(t, int(event.Method), int(parsed.L7Request.Method))
	assert.Equal(t, event.StatementId, parsed.L7Request.StatementId)
	assert.Equal(t, event.PayloadSize, parsed.L7Request.PayloadSize)
	assert.Equal(t, event.ResponseSize, parsed.L7Request.ResponseSize)
	assert.Equal(t, []byte{1, 2, 3, 4, 5}, parsed.L7Request.Payload)
	assert.Equal(t, []byte{6, 7, 8}, parsed.L7Request.Response)

	// Test short buffer
	_, err = parseL7Event(data[:len(data)-1])
	assert.Error(t, err)
}

func TestParseTcpEvent(t *testing.T) {
	event := tcpEventStruct{
		Fd:        123,
		Timestamp: 456,
		Duration:  789,
		Type:      EventTypeConnectionClose,
		Pid:       101,
		BytesSent: 1000,
		SPort:     80,
		DPort:     443,
		SAddr:     [16]byte{10, 0, 0, 1},
		DAddr:     [16]byte{192, 168, 1, 1},
	}
	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, event))
	data := buf.Bytes()

	parsed, err := parseTcpEvent(data)
	require.NoError(t, err)

	assert.Equal(t, event.Type, parsed.Type)
	assert.Equal(t, event.Pid, parsed.Pid)
	assert.Equal(t, event.Fd, parsed.Fd)
	assert.Equal(t, event.Timestamp, parsed.Timestamp)
	assert.Equal(t, time.Duration(event.Duration), parsed.Duration)
	assert.Equal(t, uint64(1000), parsed.TrafficStats.BytesSent)
	assert.Equal(t, "[a00:1::]:80", parsed.SrcAddr.String())
}

func TestParseFileEvent(t *testing.T) {
	event := fileEventStruct{
		Type: EventTypeFileOpen,
		Pid:  123,
		Fd:   456,
		Mnt:  789,
		Log:  1,
	}
	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, event))
	data := buf.Bytes()

	parsed, err := parseFileEvent(data)
	require.NoError(t, err)

	assert.Equal(t, event.Type, parsed.Type)
	assert.Equal(t, event.Pid, parsed.Pid)
	assert.Equal(t, event.Fd, parsed.Fd)
	assert.Equal(t, event.Mnt, parsed.Mnt)
	assert.True(t, parsed.Log)
}

func TestParseProcEvent(t *testing.T) {
	event := procEventStruct{
		Type:   EventTypeProcessExit,
		Pid:    123,
		Reason: uint32(EventReasonOOMKill),
	}
	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, event))
	data := buf.Bytes()

	parsed, err := parseProcEvent(data)
	require.NoError(t, err)

	assert.Equal(t, event.Type, parsed.Type)
	assert.Equal(t, event.Pid, parsed.Pid)
	assert.Equal(t, EventReasonOOMKill, parsed.Reason)
}

func BenchmarkParseL7Event_Manual(b *testing.B) {
	event := l7EventStruct{
		Fd:          123,
		Pid:         456,
		PayloadSize: 100,
		Payload:     [4096]byte{1, 2, 3},
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, event)
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseL7Event(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTcpEvent_Manual(b *testing.B) {
	event := tcpEventStruct{
		Fd:  123,
		Pid: 456,
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, event)
	data := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseTcpEvent(data); err != nil {
			b.Fatal(err)
		}
	}
}
