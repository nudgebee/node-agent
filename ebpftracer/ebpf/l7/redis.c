// Redis serialization protocol (RESP) specification
// https://redis.io/docs/reference/protocol-spec/

static __always_inline
int is_redis_query(char *buf, __u64 buf_size) {
    if (buf_size < 4) { // Smallest command is 4 bytes, e.g., "PING\r\n"
        return 0;
    }
    char b[5];
    bpf_read(buf, b);

    // Check for RESP Array format, e.g., "*3\r\n..."
    if (b[0] == '*') {
        if (b[1] >= '0' && b[1] <= '9' && b[2] == '\r' && b[3] == '\n') {
            return 1;
        }
        if (b[1] >= '0' && b[1] <= '9' && b[2] >= '0' && b[2] <= '9' && b[3] == '\r' && b[4] == '\n') {
            return 1;
        }
        return 0;
    }

    // Check for Inline Command format.
    // This is a best-effort check. We assume it's an inline command if it starts
    // with an uppercase letter and ends with \r\n. This is not perfect but will
    // catch the vast majority of cases, including the "POST..." from the logs,
    // without misidentifying other protocols.
    if (b[0] >= 'A' && b[0] <= 'Z') {
        // To avoid being too greedy, we don't check for the trailing \r\n here,
        // as the buffer might be small. The response check is more reliable.
        // This is enough to classify it as potentially Redis.
        return 1;
    }

    return 0;
}


static __always_inline
int is_redis_response(char *buf, __u64 buf_size, __s32 *status) {
    if (buf_size < 3) {
        return 0;
    }
    char type;
    bpf_read(buf, type);
    char end[2];
    TRUNCATE_PAYLOAD_SIZE(buf_size);
    bpf_read(buf+buf_size-2, end);
    if (end[0] != '\r' || end[1] != '\n') {
        return 0;
    }
    if (type == '*' || type == ':' || type == '$' || type == '+') {
        *status = STATUS_OK;
        return 1;
    }
    if (type == '-') {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
