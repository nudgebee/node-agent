package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseL7Event(t *testing.T) {
	expected := l7Event{
		Fd:                  123,
		ConnectionTimestamp: 456,
		Pid:                 789,
		Status:              200,
		Duration:            1000,
		Protocol:            1,
		Method:              2,
		Padding:             0,
		StatementId:         3,
		PayloadSize:         100,
		ResponseSize:        200,
	}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, expected))

	data := buf.Bytes()
	var actual l7Event
	require.True(t, parseL7Event(data, &actual))

	// Check fields
	assert.Equal(t, expected.Fd, actual.Fd)
	assert.Equal(t, expected.ConnectionTimestamp, actual.ConnectionTimestamp)
	assert.Equal(t, expected.Pid, actual.Pid)
	assert.Equal(t, expected.Status, actual.Status)
	assert.Equal(t, expected.Duration, actual.Duration)
	assert.Equal(t, expected.Protocol, actual.Protocol)
	assert.Equal(t, expected.Method, actual.Method)
	assert.Equal(t, expected.StatementId, actual.StatementId)
	assert.Equal(t, expected.PayloadSize, actual.PayloadSize)
	assert.Equal(t, expected.ResponseSize, actual.ResponseSize)
	// Payload/Response are not copied by parseL7Event, so we don't check them here
}

func TestParseTCPEvent(t *testing.T) {
	expected := tcpEvent{
		Fd:            1,
		Timestamp:     2,
		Duration:      3,
		Type:          EventTypeConnectionOpen,
		Pid:           4,
		BytesSent:     5,
		BytesReceived: 6,
		SPort:         8080,
		DPort:         9090,
		Aport:         10000,
	}
	copy(expected.SAddr[:], []byte{1, 2, 3, 4})
	copy(expected.DAddr[:], []byte{5, 6, 7, 8})
	copy(expected.AAddr[:], []byte{9, 10, 11, 12})

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, expected))
	buf.Write([]byte{0, 0}) // Add padding to match C struct size (104 bytes)

	data := buf.Bytes()
	var actual tcpEvent
	require.True(t, parseTCPEvent(data, &actual))

	assert.Equal(t, expected.Fd, actual.Fd)
	assert.Equal(t, expected.Timestamp, actual.Timestamp)
	assert.Equal(t, expected.Duration, actual.Duration)
	assert.Equal(t, expected.Type, actual.Type)
	assert.Equal(t, expected.Pid, actual.Pid)
	assert.Equal(t, expected.BytesSent, actual.BytesSent)
	assert.Equal(t, expected.BytesReceived, actual.BytesReceived)
	assert.Equal(t, expected.SPort, actual.SPort)
	assert.Equal(t, expected.DPort, actual.DPort)
	assert.Equal(t, expected.Aport, actual.Aport)
	assert.Equal(t, expected.SAddr, actual.SAddr)
	assert.Equal(t, expected.DAddr, actual.DAddr)
	assert.Equal(t, expected.AAddr, actual.AAddr)
}

func TestParseFileEvent(t *testing.T) {
	expected := fileEvent{
		Type: EventTypeFileOpen,
		Pid:  123,
		Fd:   456,
		Mnt:  789,
		Log:  1,
	}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, expected))

	data := buf.Bytes()
	var actual fileEvent
	require.True(t, parseFileEvent(data, &actual))

	assert.Equal(t, expected.Type, actual.Type)
	assert.Equal(t, expected.Pid, actual.Pid)
	assert.Equal(t, expected.Fd, actual.Fd)
	assert.Equal(t, expected.Mnt, actual.Mnt)
	assert.Equal(t, expected.Log, actual.Log)
}

func TestParseProcEvent(t *testing.T) {
	expected := procEvent{
		Type:   EventTypeProcessStart,
		Pid:    123,
		Reason: 1,
	}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, expected))

	data := buf.Bytes()
	var actual procEvent
	require.True(t, parseProcEvent(data, &actual))

	assert.Equal(t, expected.Type, actual.Type)
	assert.Equal(t, expected.Pid, actual.Pid)
	assert.Equal(t, expected.Reason, actual.Reason)
}
