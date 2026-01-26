package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// Legacy struct for benchmark comparison
type l7EventLegacy struct {
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

func TestParseL7Event(t *testing.T) {
	// Construct a sample byte slice
	header := l7EventLegacy{
		Fd:                  123,
		ConnectionTimestamp: 456,
		Pid:                 789,
		Status:              200,
		Duration:            1000,
		Protocol:            1,
		Method:              2,
		StatementId:         999,
		PayloadSize:         5,
		ResponseSize:        5,
	}
	copy(header.Payload[:], []byte("hello"))
	copy(header.Response[:], []byte("world"))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, &header)
	assert.NoError(t, err)

	data := buf.Bytes()

	// Test parsing
	event, err := parseL7Event(data)
	assert.NoError(t, err)

	assert.Equal(t, EventTypeL7Request, event.Type)
	assert.Equal(t, uint64(123), event.Fd)
	assert.Equal(t, uint64(456), event.Timestamp)
	assert.Equal(t, uint32(789), event.Pid)
	assert.NotNil(t, event.L7Request)
	assert.Equal(t, time.Duration(1000), event.L7Request.Duration)
	assert.Equal(t, []byte("hello"), event.L7Request.Payload)
	assert.Equal(t, []byte("world"), event.L7Request.Response)
}

func TestParseTcpEvent(t *testing.T) {
	// 102 bytes
	data := make([]byte, 102)
	binary.LittleEndian.PutUint64(data[0:], 1001) // Fd
	binary.LittleEndian.PutUint64(data[8:], 2002) // Timestamp
	binary.LittleEndian.PutUint64(data[16:], 50)  // Duration
	binary.LittleEndian.PutUint32(data[24:], uint32(EventTypeConnectionClose))
	binary.LittleEndian.PutUint32(data[28:], 123)  // Pid
	binary.LittleEndian.PutUint64(data[32:], 100)  // BytesSent
	binary.LittleEndian.PutUint64(data[40:], 200)  // BytesReceived
	binary.LittleEndian.PutUint16(data[48:], 8080) // SPort
	binary.LittleEndian.PutUint16(data[50:], 9090) // DPort
	binary.LittleEndian.PutUint16(data[52:], 9091) // APort

	// SAddr, DAddr, AAddr are zero

	event, err := parseTcpEvent(data)
	assert.NoError(t, err)
	assert.Equal(t, EventTypeConnectionClose, event.Type)
	assert.Equal(t, uint64(1001), event.Fd)
	assert.Equal(t, uint32(123), event.Pid)
	assert.NotNil(t, event.TrafficStats)
	assert.Equal(t, uint64(100), event.TrafficStats.BytesSent)
	assert.Equal(t, uint64(200), event.TrafficStats.BytesReceived)
}

func BenchmarkBinaryReadL7(b *testing.B) {
	var event l7EventLegacy
	data := make([]byte, unsafe.Sizeof(event))
	binary.LittleEndian.PutUint64(data[0:], 12345) // Fd

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var v l7EventLegacy
		_ = binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &v)
	}
}

func BenchmarkManualParseL7(b *testing.B) {
	var event l7EventLegacy
	data := make([]byte, unsafe.Sizeof(event))
	// Set payload sizes to something non-zero to test copy overhead
	// But small enough to be realistic
	binary.LittleEndian.PutUint64(data[40:], 100) // PayloadSize
	binary.LittleEndian.PutUint64(data[48:], 100) // ResponseSize

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseL7Event(data)
	}
}
