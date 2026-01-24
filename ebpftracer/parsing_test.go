package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Test to verify correctness of manual parsing vs binary.Read
func TestL7EventManualCorrectness(t *testing.T) {
	original := &l7Event{
		Fd:                  123,
		ConnectionTimestamp: 456,
		Pid:                 789,
		Status:              200,
		Duration:            1000,
		Protocol:            1,
		Method:              2,
		StatementId:         333,
		PayloadSize:         10,
		ResponseSize:        20,
	}
	copy(original.Payload[:], []byte("request-payload"))
	copy(original.Response[:], []byte("response-payload"))

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, original); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	parsed := &l7Event{}
	if err := parseL7Event(data, parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Fd != original.Fd {
		t.Errorf("Fd mismatch: %v != %v", parsed.Fd, original.Fd)
	}
	if parsed.Pid != original.Pid {
		t.Errorf("Pid mismatch: %v != %v", parsed.Pid, original.Pid)
	}
	if parsed.Status != original.Status {
		t.Errorf("Status mismatch: %v != %v", parsed.Status, original.Status)
	}
	if !bytes.Equal(parsed.Payload[:original.PayloadSize], original.Payload[:original.PayloadSize]) {
		t.Error("Payload mismatch")
	}
	if !bytes.Equal(parsed.Response[:original.ResponseSize], original.Response[:original.ResponseSize]) {
		t.Error("Response mismatch")
	}
}

func TestTcpEventManualCorrectness(t *testing.T) {
	original := &tcpEvent{
		Fd:    999,
		Pid:   888,
		SPort: 1000,
		DPort: 80,
	}
	// Set some bytes in SAddr
	original.SAddr[0] = 10
	original.SAddr[15] = 1

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, original); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	parsed := &tcpEvent{}
	if err := parseTcpEvent(data, parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Fd != original.Fd {
		t.Errorf("Fd mismatch: %v != %v", parsed.Fd, original.Fd)
	}
	if parsed.Pid != original.Pid {
		t.Errorf("Pid mismatch: %v != %v", parsed.Pid, original.Pid)
	}
	if parsed.SPort != original.SPort {
		t.Errorf("SPort mismatch: %v != %v", parsed.SPort, original.SPort)
	}
	if parsed.SAddr != original.SAddr {
		t.Errorf("SAddr mismatch: %v != %v", parsed.SAddr, original.SAddr)
	}
}

func TestProcEventManualCorrectness(t *testing.T) {
	original := &procEvent{
		Type:   EventTypeProcessStart,
		Pid:    12345,
		Reason: 1,
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, original); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	parsed := &procEvent{}
	if err := parseProcEvent(data, parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Type != original.Type {
		t.Errorf("Type mismatch: %v != %v", parsed.Type, original.Type)
	}
	if parsed.Pid != original.Pid {
		t.Errorf("Pid mismatch: %v != %v", parsed.Pid, original.Pid)
	}
	if parsed.Reason != original.Reason {
		t.Errorf("Reason mismatch: %v != %v", parsed.Reason, original.Reason)
	}
}

func TestFileEventManualCorrectness(t *testing.T) {
	original := &fileEvent{
		Type: EventTypeFileOpen,
		Pid:  54321,
		Fd:   99,
		Mnt:  88,
		Log:  77,
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, original); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	parsed := &fileEvent{}
	if err := parseFileEvent(data, parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Type != original.Type {
		t.Errorf("Type mismatch: %v != %v", parsed.Type, original.Type)
	}
	if parsed.Pid != original.Pid {
		t.Errorf("Pid mismatch: %v != %v", parsed.Pid, original.Pid)
	}
	if parsed.Fd != original.Fd {
		t.Errorf("Fd mismatch: %v != %v", parsed.Fd, original.Fd)
	}
	if parsed.Mnt != original.Mnt {
		t.Errorf("Mnt mismatch: %v != %v", parsed.Mnt, original.Mnt)
	}
	if parsed.Log != original.Log {
		t.Errorf("Log mismatch: %v != %v", parsed.Log, original.Log)
	}
}
