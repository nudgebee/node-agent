
static __always_inline
int is_http_request(char *buf) {
    char b[16];
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 8) { // Need at least "GET / HTTP/1.1"
        return 0;
    }

    // Check for a valid HTTP method and then for " HTTP/"
    if ((b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') ||
        (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') ||
        (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ') ||
        (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') ||
        (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E' && b[6] == ' ') ||
        (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T' && b[7] == ' ') ||
        (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S' && b[7] == ' ') ||
        (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H' && b[5] == ' ')) {

        // Search for " HTTP/1." to confirm it's a valid HTTP/1.x request
        #pragma unroll
        for (int i = 3; i < 16 - 7; i++) {
            if (b[i] == ' ' && b[i+1] == 'H' && b[i+2] == 'T' && b[i+3] == 'T' && b[i+4] == 'P' && b[i+5] == '/') {
                return 1;
            }
        }
    }

    return 0;
}

static __always_inline
int is_http_response(char *buf, __s32 *status) {
    char b[16];
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 16) {
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
