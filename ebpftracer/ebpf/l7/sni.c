// TLS ClientHello detection.
//
// TLS handshake records (record type 0x16) are sent in plaintext over TCP and
// pass through the regular write() syscall path. By matching them at
// trace_enter_write time we capture the SNI hostname for outbound HTTPS
// connections, which is needed for LLM provider detection on connections
// where HPACK :authority decoding is unavailable (mid-stream join after the
// agent attaches to a long-lived HTTP/2 client).
//
// User-space parses the ClientHello body and extracts SNI from the
// server_name extension (type 0x00). This file only does the cheap signature
// match: enough bytes exist, record type is handshake (0x16), record version
// is TLS 1.0-1.3 (0x03 0x01..0x04), handshake message type is ClientHello
// (0x01).

static inline __attribute__((__always_inline__))
int is_tls_clienthello(char *payload, __u64 size) {
    // Minimum bytes: 5-byte TLS record header + 1-byte handshake type.
    if (size < 6) return 0;
    char first[6];
    if (bpf_probe_read(first, sizeof(first), payload)) return 0;
    if (first[0] != 0x16) return 0;          // record type: handshake
    if (first[1] != 0x03) return 0;          // record version major: TLS
    if (first[2] > 0x04) return 0;           // record version minor: 1.0-1.3
    if (first[5] != 0x01) return 0;          // handshake type: ClientHello
    return 1;
}
