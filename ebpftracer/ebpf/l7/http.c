
static __always_inline
int is_valid_http_char(char c) {
    // Valid HTTP header characters: printable ASCII except control chars
    return (c >= 0x21 && c <= 0x7E) || c == 0x20 || c == 0x09; // printable + space + tab
}

static __always_inline
int is_binary_data(char *buf, int len) {
    // Quick binary data detection - check for common binary signatures
    if (len < 4) return 0;
    
    // TLS handshake detection (starts with 0x16 0x03)
    if (buf[0] == 0x16 && buf[1] == 0x03) {
        return 1;
    }
    
    // Check for high percentage of non-printable chars (>25% indicates binary)
    // Use fixed bounds to avoid eBPF verifier issues
    int non_printable = 0;
    int actual_len = len < 16 ? len : 16;
    
    // Manual unroll to avoid verifier back-edge issues
    if (actual_len > 0 && buf[0] < 0x20 && buf[0] != 0x09 && buf[0] != 0x0A && buf[0] != 0x0D) non_printable++;
    if (actual_len > 1 && buf[1] < 0x20 && buf[1] != 0x09 && buf[1] != 0x0A && buf[1] != 0x0D) non_printable++;
    if (actual_len > 2 && buf[2] < 0x20 && buf[2] != 0x09 && buf[2] != 0x0A && buf[2] != 0x0D) non_printable++;
    if (actual_len > 3 && buf[3] < 0x20 && buf[3] != 0x09 && buf[3] != 0x0A && buf[3] != 0x0D) non_printable++;
    if (actual_len > 4 && buf[4] < 0x20 && buf[4] != 0x09 && buf[4] != 0x0A && buf[4] != 0x0D) non_printable++;
    if (actual_len > 5 && buf[5] < 0x20 && buf[5] != 0x09 && buf[5] != 0x0A && buf[5] != 0x0D) non_printable++;
    if (actual_len > 6 && buf[6] < 0x20 && buf[6] != 0x09 && buf[6] != 0x0A && buf[6] != 0x0D) non_printable++;
    if (actual_len > 7 && buf[7] < 0x20 && buf[7] != 0x09 && buf[7] != 0x0A && buf[7] != 0x0D) non_printable++;
    if (actual_len > 8 && buf[8] < 0x20 && buf[8] != 0x09 && buf[8] != 0x0A && buf[8] != 0x0D) non_printable++;
    if (actual_len > 9 && buf[9] < 0x20 && buf[9] != 0x09 && buf[9] != 0x0A && buf[9] != 0x0D) non_printable++;
    if (actual_len > 10 && buf[10] < 0x20 && buf[10] != 0x09 && buf[10] != 0x0A && buf[10] != 0x0D) non_printable++;
    if (actual_len > 11 && buf[11] < 0x20 && buf[11] != 0x09 && buf[11] != 0x0A && buf[11] != 0x0D) non_printable++;
    if (actual_len > 12 && buf[12] < 0x20 && buf[12] != 0x09 && buf[12] != 0x0A && buf[12] != 0x0D) non_printable++;
    if (actual_len > 13 && buf[13] < 0x20 && buf[13] != 0x09 && buf[13] != 0x0A && buf[13] != 0x0D) non_printable++;
    if (actual_len > 14 && buf[14] < 0x20 && buf[14] != 0x09 && buf[14] != 0x0A && buf[14] != 0x0D) non_printable++;
    if (actual_len > 15 && buf[15] < 0x20 && buf[15] != 0x09 && buf[15] != 0x0A && buf[15] != 0x0D) non_printable++;
    
    return (non_printable > (actual_len / 4)); // >25% non-printable
}

static __always_inline
int validate_http_structure(char *buf, int len) {
    // Must have minimum structure: METHOD + SPACE + URI + SPACE + VERSION
    if (len < 14) return 0; // "GET / HTTP/1.1" = 14 chars minimum
    
    // Find first space (after method) - manual unroll to avoid verifier issues
    int space1_pos = -1;
    if (len > 3 && buf[3] == ' ') space1_pos = 3;
    else if (len > 4 && buf[4] == ' ') space1_pos = 4;
    else if (len > 5 && buf[5] == ' ') space1_pos = 5;
    else if (len > 6 && buf[6] == ' ') space1_pos = 6;
    else if (len > 7 && buf[7] == ' ') space1_pos = 7;
    else if (len > 8 && buf[8] == ' ') space1_pos = 8;
    else if (len > 9 && buf[9] == ' ') space1_pos = 9;
    else if (len > 10 && buf[10] == ' ') space1_pos = 10;
    else if (len > 11 && buf[11] == ' ') space1_pos = 11;
    
    if (space1_pos == -1 || space1_pos > 10) return 0; // No space or method too long
    
    // Check URI starts with '/' or 'h' (for http://...)
    if (buf[space1_pos + 1] != '/' && buf[space1_pos + 1] != 'h') return 0;
    
    // Find second space (after URI) - manual unroll to avoid verifier issues
    int space2_pos = -1;
    int search_start = space1_pos + 2;
    int search_end = len < search_start + 32 ? len : search_start + 32; // Limit to 32 chars for manual unroll
    
    // Manual unroll for up to 32 positions to find space after URI
    if (search_start < search_end && buf[search_start] == ' ') space2_pos = search_start;
    else if (search_start + 1 < search_end && buf[search_start + 1] == ' ') space2_pos = search_start + 1;
    else if (search_start + 2 < search_end && buf[search_start + 2] == ' ') space2_pos = search_start + 2;
    else if (search_start + 3 < search_end && buf[search_start + 3] == ' ') space2_pos = search_start + 3;
    else if (search_start + 4 < search_end && buf[search_start + 4] == ' ') space2_pos = search_start + 4;
    else if (search_start + 5 < search_end && buf[search_start + 5] == ' ') space2_pos = search_start + 5;
    else if (search_start + 6 < search_end && buf[search_start + 6] == ' ') space2_pos = search_start + 6;
    else if (search_start + 7 < search_end && buf[search_start + 7] == ' ') space2_pos = search_start + 7;
    else if (search_start + 8 < search_end && buf[search_start + 8] == ' ') space2_pos = search_start + 8;
    else if (search_start + 9 < search_end && buf[search_start + 9] == ' ') space2_pos = search_start + 9;
    else if (search_start + 10 < search_end && buf[search_start + 10] == ' ') space2_pos = search_start + 10;
    else if (search_start + 11 < search_end && buf[search_start + 11] == ' ') space2_pos = search_start + 11;
    else if (search_start + 12 < search_end && buf[search_start + 12] == ' ') space2_pos = search_start + 12;
    else if (search_start + 13 < search_end && buf[search_start + 13] == ' ') space2_pos = search_start + 13;
    else if (search_start + 14 < search_end && buf[search_start + 14] == ' ') space2_pos = search_start + 14;
    else if (search_start + 15 < search_end && buf[search_start + 15] == ' ') space2_pos = search_start + 15;
    
    if (space2_pos == -1) return 0; // No second space found
    
    // Check for HTTP version pattern
    if (space2_pos + 8 > len) return 0; // Not enough space for "HTTP/1.1"
    if (buf[space2_pos + 1] != 'H' || buf[space2_pos + 2] != 'T' || 
        buf[space2_pos + 3] != 'T' || buf[space2_pos + 4] != 'P' || 
        buf[space2_pos + 5] != '/') return 0;
    
    return 1;
}

static __always_inline
int is_http_request(char *buf) {
    char b[64]; // Increased buffer for better validation
    int read_len = bpf_probe_read_user_str(b, sizeof(b), (void *)buf);
    if (read_len < 14) { // Minimum "GET / HTTP/1.1"
        return 0;
    }
    
    // Quick binary data rejection
    if (is_binary_data(b, read_len)) {
        return 0;
    }
    
    // Method validation with space requirement
    int method_matched = 0;
    
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && 
               b[4] == 'T' && b[5] == 'E' && b[6] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && 
               b[4] == 'E' && b[5] == 'C' && b[6] == 'T' && b[7] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && 
               b[4] == 'O' && b[5] == 'N' && b[6] == 'S' && b[7] == ' ') {
        method_matched = 1;
    } else if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && 
               b[4] == 'H' && b[5] == ' ') {
        method_matched = 1;
    }
    
    if (!method_matched) {
        return 0;
    }
    
    // Validate complete HTTP structure
    return validate_http_structure(b, read_len);
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char b[32]; // Increased buffer for better validation
    int read_len = bpf_probe_read_user_str(b, sizeof(b), (void *)buf);
    if (read_len < 12) { // Minimum "HTTP/1.1 200"
        return 0;
    }
    
    // Quick binary data rejection for responses too
    if (is_binary_data(b, read_len)) {
        return 0;
    }
    
    // Strict HTTP response validation
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return 0;
    }
    
    // Version validation: 1.0, 1.1, 2.0
    if (b[5] < '1' || b[5] > '2') {
        return 0;
    }
    if (b[6] != '.') {
        return 0;
    }
    if (b[7] < '0' || b[7] > '1') {
        return 0;
    }
    if (b[8] != ' ') {
        return 0;
    }
    
    // Status code validation (3 digits)
    if (b[9] < '1' || b[9] > '5' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return 0;
    }
    
    // Optional: validate status code ranges
    int status_code = (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
    if (status_code < 100 || status_code > 599) {
        return 0;
    }
    
    // Must have space or end after status code
    if (read_len > 12 && b[12] != ' ' && b[12] != '\r' && b[12] != '\n') {
        return 0;
    }
    
    *status = status_code;
    return 1;
}
