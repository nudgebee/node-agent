#define HTTP2_CLIENT_INITIATED_STREAM(stream_id) (stream_id & 0x01000000) // big-endian (network byte order) odd number
#define HTTP2_SETTINGS_FRAME 0x4

#define bpf_read(src, dst) bpf_probe_read(&dst, sizeof(dst), src)

static __always_inline
int is_client_preface(char *buf, __u64 size, __u8 method) {
    if (method != METHOD_HTTP2_CLIENT_FRAMES || size < 24) {
        return 0;
    }
    char b[5];
    bpf_read(buf, b);
    if (b[0] == 'P' && b[1]=='R' && b[2]=='I' && b[3]==' ' && b[4]=='*') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_server_preface(__u8 frame_type, __u32 stream_id, __u8 method) {
    return method == METHOD_HTTP2_SERVER_FRAMES && frame_type == HTTP2_SETTINGS_FRAME && stream_id == 0;
}

static __always_inline
int looks_like_http2_frame(char *buf, __u64 size, __u8 method) {
    __u32 frame_length;
    bpf_read(buf, frame_length);
    frame_length = bpf_htonl(frame_length) >> 8;
    if (frame_length + 9 > size) {
        return is_client_preface(buf, size, method);
    }
    __u8 frame_type;
    bpf_read(buf+3, frame_type);
    if (frame_type > 0x9) {
        return is_client_preface(buf, size, method);
    }
    __u32 stream_id;
    bpf_read(buf+5, stream_id);
    if (!HTTP2_CLIENT_INITIATED_STREAM(stream_id)) {
        return is_server_preface(frame_type, stream_id, method);
    }
    return 1;
}

static __always_inline
int is_http2_response_partial(char *buf, __u64 size, __u8 partial) {
    // If this is a continuation of a partial response
    if (partial) {
        return 1; // Continue collecting HTTP/2 frames
    }
    
    // Need at least 9 bytes for HTTP/2 frame header
    if (size < 9) {
        return 2; // Partial, need more data
    }
    
    // Check if this looks like HTTP/2 frames
    if (!looks_like_http2_frame(buf, size, METHOD_HTTP2_SERVER_FRAMES)) {
        return 0; // Not HTTP/2
    }
    
    // Parse frame header to check completeness
    __u32 frame_length;
    bpf_read(buf, frame_length);
    frame_length = bpf_htonl(frame_length) >> 8; // Get 24-bit length
    
    __u8 frame_type;
    bpf_read(buf + 3, frame_type);
    
    __u8 flags;
    bpf_read(buf + 4, flags);
    
    // Check if we have the complete frame
    if (size < frame_length + 9) {
        return 2; // Incomplete frame, need more data
    }
    
    // For DATA frames (0x0), check if END_STREAM flag (0x1) is set
    if (frame_type == 0x0) { // DATA frame
        if (!(flags & 0x1)) { // END_STREAM flag not set
            return 2; // More DATA frames expected
        }
    }
    
    // For HEADERS frames (0x1), check if END_HEADERS flag (0x4) is set
    if (frame_type == 0x1) { // HEADERS frame
        if (!(flags & 0x4)) { // END_HEADERS flag not set
            return 2; // More HEADERS/CONTINUATION frames expected
        }
    }
    
    return 1; // Complete response or frame sequence
}