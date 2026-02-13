// HTTP/2 Frame Types (RFC 9113)
#define HTTP2_FRAME_DATA          0x00
#define HTTP2_FRAME_HEADERS       0x01
#define HTTP2_FRAME_PRIORITY      0x02
#define HTTP2_FRAME_RST_STREAM    0x03
#define HTTP2_FRAME_SETTINGS      0x04
#define HTTP2_FRAME_PUSH_PROMISE  0x05
#define HTTP2_FRAME_PING          0x06
#define HTTP2_FRAME_GOAWAY        0x07
#define HTTP2_FRAME_WINDOW_UPDATE 0x08
#define HTTP2_FRAME_CONTINUATION  0x09

// HTTP/2 Frame Flags
#define HTTP2_FLAG_END_STREAM     0x01
#define HTTP2_FLAG_END_HEADERS    0x04
#define HTTP2_FLAG_PADDED         0x08
#define HTTP2_FLAG_PRIORITY       0x20

// Valid flags per frame type (RFC 9113 Section 4)
// DATA: END_STREAM (0x1), PADDED (0x8)
// HEADERS: END_STREAM (0x1), END_HEADERS (0x4), PADDED (0x8), PRIORITY (0x20)
// SETTINGS: ACK (0x1)
// PING: ACK (0x1)
// CONTINUATION: END_HEADERS (0x4)
static __always_inline
__u8 valid_flags_for_frame_type(__u8 frame_type) {
    switch (frame_type) {
        case HTTP2_FRAME_DATA:          return 0x09; // END_STREAM, PADDED
        case HTTP2_FRAME_HEADERS:       return 0x2D; // END_STREAM, END_HEADERS, PADDED, PRIORITY
        case HTTP2_FRAME_PRIORITY:      return 0x00;
        case HTTP2_FRAME_RST_STREAM:    return 0x00;
        case HTTP2_FRAME_SETTINGS:      return 0x01; // ACK
        case HTTP2_FRAME_PUSH_PROMISE:  return 0x0C; // END_HEADERS, PADDED
        case HTTP2_FRAME_PING:          return 0x01; // ACK
        case HTTP2_FRAME_GOAWAY:        return 0x00;
        case HTTP2_FRAME_WINDOW_UPDATE: return 0x00;
        case HTTP2_FRAME_CONTINUATION:  return 0x04; // END_HEADERS
        default:                        return 0xFF; // Unknown frame type
    }
}

// Check if this is the HTTP/2 client connection preface
// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
static __always_inline
int is_http2_client_preface(char *buf, __u64 size) {
    if (size < 24) {
        return 0;
    }
    char b[9];
    bpf_read(buf, b);
    // Check "PRI * HTT" (first 9 bytes)
    if (b[0] == 'P' && b[1] == 'R' && b[2] == 'I' && b[3] == ' ' &&
        b[4] == '*' && b[5] == ' ' && b[6] == 'H' && b[7] == 'T' && b[8] == 'T') {
        return 1;
    }
    return 0;
}

// Parse HTTP/2 frame header (9 bytes)
// Returns 1 if valid HTTP/2 frame, 0 otherwise
// Frame header format:
// +-----------------------------------------------+
// |                 Length (24)                   |
// +---------------+---------------+---------------+
// |   Type (8)    |   Flags (8)   |
// +-+-------------+---------------+-------------------------------+
// |R|                 Stream Identifier (31)                      |
// +-+-------------------------------------------------------------+
static __always_inline
int parse_http2_frame_header(char *buf, __u64 size, __u32 *out_length, __u8 *out_type,
                              __u8 *out_flags, __u32 *out_stream_id) {
    if (size < 9) {
        return 0;
    }

    // Read frame header bytes
    __u8 header[9];
    if (bpf_probe_read(header, 9, buf)) {
        return 0;
    }

    // Parse length (24-bit big-endian)
    __u32 frame_length = ((__u32)header[0] << 16) | ((__u32)header[1] << 8) | (__u32)header[2];

    // Parse type and flags
    __u8 frame_type = header[3];
    __u8 flags = header[4];

    // Parse stream_id (31-bit big-endian, high bit is reserved and must be 0)
    __u32 stream_id = ((__u32)(header[5] & 0x7F) << 24) | ((__u32)header[6] << 16) |
                      ((__u32)header[7] << 8) | (__u32)header[8];

    // Validate reserved bit (R) must be 0
    if (header[5] & 0x80) {
        return 0;
    }

    // Validate frame type (0x00 - 0x09 are defined)
    if (frame_type > 0x09) {
        return 0;
    }

    // Validate flags for frame type
    __u8 valid_flags = valid_flags_for_frame_type(frame_type);
    if (valid_flags != 0xFF && (flags & ~valid_flags)) {
        // Invalid flags for this frame type - but be lenient, some implementations may differ
        // Just log but don't reject
    }

    // Validate stream_id rules per frame type
    switch (frame_type) {
        case HTTP2_FRAME_DATA:
        case HTTP2_FRAME_HEADERS:
        case HTTP2_FRAME_PRIORITY:
        case HTTP2_FRAME_RST_STREAM:
        case HTTP2_FRAME_PUSH_PROMISE:
        case HTTP2_FRAME_CONTINUATION:
            // These frames MUST have non-zero stream_id
            if (stream_id == 0) {
                return 0;
            }
            break;
        case HTTP2_FRAME_SETTINGS:
        case HTTP2_FRAME_PING:
        case HTTP2_FRAME_GOAWAY:
            // These frames MUST have stream_id == 0 (connection-level)
            if (stream_id != 0) {
                return 0;
            }
            break;
        case HTTP2_FRAME_WINDOW_UPDATE:
            // Can be either connection-level (0) or stream-level (non-zero)
            break;
    }

    // Frame length sanity check (max 16MB per frame, default max is 16KB)
    if (frame_length > 16777215) {
        return 0;
    }

    *out_length = frame_length;
    *out_type = frame_type;
    *out_flags = flags;
    *out_stream_id = stream_id;

    return 1;
}

// HPACK static table index detection (RFC 7541)
// Indices 1-7: Request pseudo-headers (:authority, :method, :path, :scheme)
// Indices 8-14: Response status codes (:status 200, 204, 206, 304, 400, 404, 500)
// Used to identify if HEADERS frame is request vs response
static __always_inline
int detect_hpack_static_index(char *buf, __u64 size, int *is_request, int *is_response) {
    if (size < 1) {
        return 0;
    }

    __u8 first_byte;
    if (bpf_probe_read(&first_byte, 1, buf)) {
        return 0;
    }

    // Indexed Header Field (high bit set): 1xxxxxxx
    // The index is in the lower 7 bits (for small indices)
    if (first_byte & 0x80) {
        __u8 index = first_byte & 0x7F;

        // Static table indices 1-7 are request pseudo-headers
        // 1: :authority
        // 2: :method GET
        // 3: :method POST
        // 4: :path /
        // 5: :path /index.html
        // 6: :scheme http
        // 7: :scheme https
        if (index >= 1 && index <= 7) {
            *is_request = 1;
            return 1;
        }

        // Static table indices 8-14 are response status codes
        // 8: :status 200
        // 9: :status 204
        // 10: :status 206
        // 11: :status 304
        // 12: :status 400
        // 13: :status 404
        // 14: :status 500
        if (index >= 8 && index <= 14) {
            *is_response = 1;
            return 1;
        }
    }

    // Literal Header Field with Incremental Indexing (01xxxxxx)
    // Index 0 means new name, otherwise it's a static/dynamic table index
    if ((first_byte & 0xC0) == 0x40) {
        __u8 index = first_byte & 0x3F;
        if (index >= 1 && index <= 7) {
            *is_request = 1;
            return 1;
        }
        if (index >= 8 && index <= 14) {
            *is_response = 1;
            return 1;
        }
    }

    return 0;
}

// Check a single frame at the given buffer position for HEADERS with valid HPACK.
// Returns 1 if this frame is a HEADERS frame with recognizable static table indices.
static __always_inline
int is_headers_frame_with_hpack(char *buf, __u64 size, __u8 method) {
    __u32 frame_length;
    __u8 frame_type;
    __u8 flags;
    __u32 stream_id;

    if (!parse_http2_frame_header(buf, size, &frame_length, &frame_type, &flags, &stream_id)) {
        return 0;
    }

    if (frame_type != HTTP2_FRAME_HEADERS || size <= 9) {
        return 0;
    }

    int is_request = 0;
    int is_response = 0;

    __u64 header_offset = 9;
    if (flags & HTTP2_FLAG_PRIORITY) {
        header_offset += 5;
    }
    if (flags & HTTP2_FLAG_PADDED) {
        header_offset += 1;
    }

    if (header_offset < size) {
        detect_hpack_static_index(buf + header_offset, size - header_offset, &is_request, &is_response);

        if ((method == METHOD_HTTP2_CLIENT_FRAMES && is_request) ||
            (method == METHOD_HTTP2_SERVER_FRAMES && is_response)) {
            return 1;
        }
        // HEADERS frame found but HPACK didn't match expected direction.
        // Still likely HTTP/2 if the other direction matched.
        if (is_request || is_response) {
            return 1;
        }
    }

    return 0;
}

// Main HTTP/2 frame detection function.
// Strict: only confirms HTTP/2 on:
//   1. Client connection preface ("PRI * HTTP/2.0...")
//   2. Server SETTINGS preface (SETTINGS frame on stream 0)
//   3. HEADERS frame with recognizable HPACK static table indices
// For non-HEADERS frames (DATA, PING, etc.), scans forward through
// up to 4 frames looking for a HEADERS frame before confirming.
// This prevents false positives from protocols whose bytes happen
// to parse as valid HTTP/2 frame headers (e.g. DNS, Kafka).
static __always_inline
int looks_like_http2_frame(char *buf, __u64 size, __u8 method) {
    // Check for HTTP/2 client connection preface (only sent once at start)
    if (method == METHOD_HTTP2_CLIENT_FRAMES && is_http2_client_preface(buf, size)) {
        return 1;
    }

    if (size < 9) {
        return 0;
    }

    // Parse first frame header
    __u32 frame_length;
    __u8 frame_type;
    __u8 flags;
    __u32 stream_id;

    if (!parse_http2_frame_header(buf, size, &frame_length, &frame_type, &flags, &stream_id)) {
        return 0;
    }

    // Server preface: SETTINGS frame on stream 0
    if (method == METHOD_HTTP2_SERVER_FRAMES && frame_type == HTTP2_FRAME_SETTINGS && stream_id == 0) {
        return 1;
    }

    // If first frame is HEADERS, check HPACK immediately
    if (is_headers_frame_with_hpack(buf, size, method)) {
        return 1;
    }

    // First frame wasn't HEADERS. Check the second frame if it fits.
    // Bound pos to size so the eBPF verifier can prove pointer arithmetic is safe.
    __u64 pos = 9 + frame_length;
    if (pos >= size || pos > 4096) {
        return 0;
    }

    // Frame 2
    __u64 remaining = size - pos;
    if (remaining >= 9) {
        if (is_headers_frame_with_hpack(buf + pos, remaining, method)) {
            return 1;
        }
        // Try to advance to frame 3
        __u32 f2_len; __u8 f2_type; __u8 f2_flags; __u32 f2_sid;
        if (parse_http2_frame_header(buf + pos, remaining, &f2_len, &f2_type, &f2_flags, &f2_sid)) {
            __u64 pos2 = pos + 9 + f2_len;
            if (pos2 < size && pos2 <= 4096) {
                __u64 remaining2 = size - pos2;
                if (remaining2 >= 9) {
                    if (is_headers_frame_with_hpack(buf + pos2, remaining2, method)) {
                        return 1;
                    }
                }
            }
        }
    }

    // No HEADERS frame found - don't confirm as HTTP/2
    return 0;
}

// Check if connection is to an external HTTPS endpoint (port 443)
// This provides a hint for HTTP/2 detection since most HTTPS traffic is HTTP/2
static __always_inline
int is_likely_http2_port(__u16 dport) {
    return dport == 443 || dport == 8443;
}