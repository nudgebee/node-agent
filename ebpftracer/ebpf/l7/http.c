
static __always_inline
int is_http_request(char *buf) {
    char b[16];
    if (bpf_probe_read(&b, sizeof(b), (void *)buf)) {
        return 0;
    }
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') {
        return 1;
    }
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') {
        return 1;
    }
    if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E') {
        return 1;
    }
    if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T') {
        return 1;
    }
    if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char b[16];
    if (bpf_probe_read(&b, sizeof(b), (void *)buf)) {
        return 0;
    }
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return 0;
    }
    if (b[5] < '0' || b[5] > '9') {
        return 0;
    }
    if (b[6] != '.') {
        return 0;
    }
    if (b[7] < '0' || b[7] > '9') {
        return 0;
    }
    if (b[8] != ' ') {
        return 0;
    }
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return 0;
    }
    *status = (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
    return 1;
}

static __always_inline
int is_http_response_partial(char *buf, __u64 size, __u8 partial) {
    // If this is a continuation of a partial response
    if (partial) {
        return 1; // Assume it's part of the ongoing HTTP response
    }
    
    // Check if we have enough data for a complete HTTP response
    if (size < 4) {
        return 2; // Mark as partial, need more data
    }
    
    __s32 status;
    if (!is_http_response(buf, &status)) {
        return 0; // Not an HTTP response
    }
    
    // Look for end of headers (double CRLF)
    char pattern[4] = {'\r', '\n', '\r', '\n'};
    __u64 header_end = 0;
    
    #pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_SIZE - 4 && i < (int)size - 4; i++) {
        char check[4];
        if (bpf_probe_read(check, 4, buf + i)) {
            break;
        }
        if (check[0] == pattern[0] && check[1] == pattern[1] && 
            check[2] == pattern[2] && check[3] == pattern[3]) {
            header_end = i + 4;
            break;
        }
    }
    
    if (header_end == 0) {
        return 2; // Headers incomplete, need more data
    }
    
    // Check Content-Length header for completeness
    // For now, assume single packet responses are complete
    // TODO: Parse Content-Length header for exact validation
    
    return 1; // Complete response
}
