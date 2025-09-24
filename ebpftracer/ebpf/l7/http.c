
static __always_inline
int is_http_request(char *buf) {
    char method[16];
    // Use modern user-space string read with proper error handling
    int bytes_read = bpf_probe_read_user_str(method, sizeof(method), buf);
    
    // Check for read errors - negative values indicate failure
    if (bytes_read <= 0) {
        return 0;
    }
    
    // HTTP method detection with space validation
    if (method[0] == 'G' && method[1] == 'E' && method[2] == 'T' && method[3] == ' ') {
        return 1;
    }
    if (method[0] == 'P' && method[1] == 'O' && method[2] == 'S' && method[3] == 'T' && method[4] == ' ') {
        return 1;
    }
    if (method[0] == 'H' && method[1] == 'E' && method[2] == 'A' && method[3] == 'D' && method[4] == ' ') {
        return 1;
    }
    if (method[0] == 'P' && method[1] == 'U' && method[2] == 'T' && method[3] == ' ') {
        return 1;
    }
    if (bytes_read >= 7 && method[0] == 'D' && method[1] == 'E' && method[2] == 'L' && method[3] == 'E' && method[4] == 'T' && method[5] == 'E' && method[6] == ' ') {
        return 1;
    }
    if (bytes_read >= 8 && method[0] == 'C' && method[1] == 'O' && method[2] == 'N' && method[3] == 'N' && method[4] == 'E' && method[5] == 'C' && method[6] == 'T' && method[7] == ' ') {
        return 1;
    }
    if (bytes_read >= 8 && method[0] == 'O' && method[1] == 'P' && method[2] == 'T' && method[3] == 'I' && method[4] == 'O' && method[5] == 'N' && method[6] == 'S' && method[7] == ' ') {
        return 1;
    }
    if (bytes_read >= 6 && method[0] == 'P' && method[1] == 'A' && method[2] == 'T' && method[3] == 'C' && method[4] == 'H' && method[5] == ' ') {
        return 1;
    }
    return 0;
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char response[16];
    // Use modern user-space string read with proper error handling
    int bytes_read = bpf_probe_read_user_str(response, sizeof(response), buf);
    
    // Check for read errors and minimum required bytes for HTTP response
    if (bytes_read < 12) {  // Need at least "HTTP/1.1 200" (12 chars)
        return 0;
    }
    
    // Validate HTTP response format: "HTTP/x.x xxx"
    if (response[0] != 'H' || response[1] != 'T' || response[2] != 'T' || response[3] != 'P' || response[4] != '/') {
        return 0;
    }
    if (response[5] < '0' || response[5] > '9') {
        return 0;
    }
    if (response[6] != '.') {
        return 0;
    }
    if (response[7] < '0' || response[7] > '9') {
        return 0;
    }
    if (response[8] != ' ') {
        return 0;
    }
    if (response[9] < '0' || response[9] > '9' || response[10] < '0' || response[10] > '9' || response[11] < '0' || response[11] > '9') {
        return 0;
    }
    
    // Extract status code
    *status = (response[9]-'0')*100 + (response[10]-'0')*10 + (response[11]-'0');
    return 1;
}
