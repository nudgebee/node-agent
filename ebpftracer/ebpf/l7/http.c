
// Minimal eBPF HTTP detection - keep it simple to avoid instruction limit
static __always_inline
int is_binary_data(char *buf, int len) {
    if (len < 2) return 0;
    
    // Quick TLS detection (most common binary protocol)
    if (buf[0] == 0x16 && buf[1] == 0x03) return 1; // TLS handshake
    if (buf[0] == 0x17 && buf[1] == 0x03) return 1; // TLS application data
    
    return 0; // Let userspace handle complex validation
}

static __always_inline
int is_http_request(char *buf) {
    char b[16]; // Small buffer for eBPF efficiency
    int read_len = bpf_probe_read_user_str(b, sizeof(b), (void *)buf);
    if (read_len < 8) { // Minimum "GET / H"
        return 0;
    }
    
    // Quick TLS rejection
    if (is_binary_data(b, read_len)) {
        return 0;
    }
    
    // Simple method detection - let userspace do full validation
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') {
        return 1;
    }
    if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') {
        return 1;
    }
    if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ') {
        return 1;
    }
    
    return 0;
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char b[16]; // Small buffer for eBPF efficiency
    int read_len = bpf_probe_read_user_str(b, sizeof(b), (void *)buf);
    if (read_len < 12) { // Minimum "HTTP/1.1 200"
        return 0;
    }
    
    // Quick TLS rejection
    if (is_binary_data(b, read_len)) {
        return 0;
    }
    
    // Simple HTTP response validation
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/' || b[8] != ' ') {
        return 0;
    }
    
    // Simple status code validation
    if (b[9] < '1' || b[9] > '5' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return 0;
    }
    
    *status = (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
    return 1;
}
