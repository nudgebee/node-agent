
// is_http_request reports whether buf starts an HTTP/1.x request. A request
// line can be longer than the bytes read here, so " HTTP/" may lie past them:
// a target in origin form (a path) or absolute form (a proxy's http:// URL)
// is enough. Requiring the version within the buffer dropped every request
// with a target longer than about 50 bytes that opened its connection. Other
// targets (CONNECT host:port, OPTIONS *) are confirmed by the version, as
// before, which is what keeps Redis inline commands and binary data out.
static __always_inline
int is_http_request(char *buf) {
    // Zeroed, as bpf_probe_read_str leaves the bytes past the string as the
    // stack had them: a previous request's " HTTP/" there passed the scan
    // below. Eight stores, where bounding the scan by the length read added a
    // branch per step and half again to the verifier's work.
    char b[64] = {};
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 8) {
        return 0;
    }
    // The first bytes of the request target, after the method and its space.
    // Constant offsets per method keep the reads below fixed for the verifier.
    char t0, t1, t2, t3;
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {
        t0 = b[4]; t1 = b[5]; t2 = b[6]; t3 = b[7];
    } else if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') {
        t0 = b[4]; t1 = b[5]; t2 = b[6]; t3 = b[7];
    } else if ((b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') ||
               (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ')) {
        t0 = b[5]; t1 = b[6]; t2 = b[7]; t3 = b[8];
    } else if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H' && b[5] == ' ') {
        t0 = b[6]; t1 = b[7]; t2 = b[8]; t3 = b[9];
    } else if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E' && b[6] == ' ') {
        t0 = b[7]; t1 = b[8]; t2 = b[9]; t3 = b[10];
    } else if ((b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T' && b[7] == ' ') ||
               (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S' && b[7] == ' ')) {
        t0 = b[8]; t1 = b[9]; t2 = b[10]; t3 = b[11];
    } else {
        return 0;
    }
    if (t0 == '/') {
        return 1;
    }
    if (t0 == 'h' && t1 == 't' && t2 == 't' && t3 == 'p') {
        return 1;
    }
    #pragma unroll
    for (int i = 3; i < sizeof(b) - 7; i++) {
        if (b[i] == ' ' && b[i+1] == 'H' && b[i+2] == 'T' && b[i+3] == 'T' && b[i+4] == 'P' && b[i+5] == '/') {
            return 1;
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
