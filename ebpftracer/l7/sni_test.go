package l7

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// makeClientHello captures a real TLS ClientHello bytes by intercepting the
// first write on a pipe. This exercises the parser against an actual
// stdlib-generated ClientHello rather than a hand-crafted one.
func makeClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	captured := make(chan []byte, 1)
	captureErr := make(chan error, 1)

	go func() {
		buf := make([]byte, 4096)
		_ = serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := serverConn.Read(buf)
		if err != nil && n == 0 {
			captureErr <- err
			return
		}
		captured <- buf[:n]
	}()

	c := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	// Handshake will block writing the ClientHello and reading a response —
	// reading times out / fails since we never send a ServerHello, but the
	// goroutine above captured the ClientHello bytes.
	_ = c.Handshake()

	select {
	case b := <-captured:
		return b
	case err := <-captureErr:
		t.Fatalf("read ClientHello: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout capturing ClientHello")
	}
	return nil
}

func TestParseSNI(t *testing.T) {
	cases := []string{
		"generativelanguage.googleapis.com",
		"api.openai.com",
		"bedrock-runtime.us-west-2.amazonaws.com",
		"a.b",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			hello := makeClientHello(t, name)
			got, err := ParseSNI(hello)
			if err != nil {
				t.Fatalf("ParseSNI(%q) error: %v", name, err)
			}
			if got != name {
				t.Fatalf("ParseSNI(%q) = %q", name, got)
			}
		})
	}
}

func TestParseSNI_Errors(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x16, 0x03, 0x01}},
		{"wrong record type", []byte{0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 0, 0}},
		{"not ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0, 0, 0, 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseSNI(c.input); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}
