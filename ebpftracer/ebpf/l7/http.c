
static __always_inline
int is_http_request(char *buf) {
    char b[16];
    if (bpf_probe_read_str(&b, sizeof(b), (void *)buf) < 0) {
        return 0;
    }

    // Check for a valid HTTP method
    int method_len = 0;
    if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T' && b[3] == ' ') {
        method_len = 3;
    } else if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T' && b[4] == ' ') {
        method_len = 4;
    } else if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D' && b[4] == ' ') {
        method_len = 4;
    } else if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T' && b[3] == ' ') {
        method_len = 3;
    } else if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E' && b[6] == ' ') {
        method_len = 6;
    } else if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T' && b[7] == ' ') {
        method_len = 7;
    } else if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S' && b[7] == ' ') {
        method_len = 7;
    } else if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H' && b[5] == ' ') {
        method_len = 5;
    } else {
        return 0;
    }

    // We scan for " HTTP/1." starting after the shortest possible method ("GET ").
    // The loop must have a constant boundary to be unrolled by the compiler and accepted by the eBPF verifier.
    #pragma unroll
    for (int i = 4; i < 128 - 8; i++) {
        char version_check[8];
        if (bpf_probe_read_str(&version_check, sizeof(version_check), (void *)(buf + i)) < 0) {
            break; // Stop if we can't read
        }
        if (version_check[0] == ' ' && version_check[1] == 'H' && version_check[2] == 'T' &&
            version_check[3] == 'T' && version_check[4] == 'P' && version_check[5] == '/' &&
            version_check[6] == '1' && version_check[7] == '.') {
            return 1; // Found " HTTP/1." - this is a valid HTTP/1.x request
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
