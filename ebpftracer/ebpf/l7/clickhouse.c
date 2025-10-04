#define CLICKHOUSE_QUERY_ID_SIZE 36

#define CLICKHOUSE_QUERY_KIND_INITIAL 1
#define CLICKHOUSE_QUERY_KIND_SECONDARY 2

#define CLICKHOUSE_CLIENT_CODE_QUERY 1

#define CLICKHOUSE_SERVER_CODE_DATA 1
#define CLICKHOUSE_SERVER_CODE_EXCEPTION 2
#define CLICKHOUSE_SERVER_CODE_END_OF_STREAM 5

static __always_inline
int is_clickhouse_query(char *buf, __u64 buf_size) {
    // Need at least the header bytes to validate ClickHouse protocol
    if (buf_size < CLICKHOUSE_QUERY_ID_SIZE+3) {
        return 0;
    }
    
    __u8 b[CLICKHOUSE_QUERY_ID_SIZE+3];
    bpf_read(buf, b);
    
    // First byte must be QUERY command
    if (b[0] != CLICKHOUSE_CLIENT_CODE_QUERY) {
        return 0;
    }
    
    int offset = 0;
    if (b[1] == 0) {
        offset = 2;
    } else if (b[1] == CLICKHOUSE_QUERY_ID_SIZE) {
        offset = 2 + CLICKHOUSE_QUERY_ID_SIZE;
    } else {
        // Invalid query ID length - not ClickHouse
        return 0;
    }
    
    // Validate query kind
    if (b[offset] != CLICKHOUSE_QUERY_KIND_INITIAL && b[offset] != CLICKHOUSE_QUERY_KIND_SECONDARY) {
        return 0;
    }
    
    // Additional validation: check for reasonable message structure
    // ClickHouse messages should have more structured content after the query kind
    if (buf_size > offset + 1) {
        // Check if the next bytes look like ClickHouse protocol continuation
        // This helps avoid false positives from AMQP frames that happen to match
        __u8 next_byte = 0;
        bpf_read(buf + offset + 1, next_byte);
        
        // AMQP frames often have specific patterns that differ from ClickHouse
        // AMQP Basic.Publish has class=60, method=40 at fixed positions
        // If we see AMQP-like patterns, reject this as ClickHouse
        if (offset == 2 && buf_size >= 9) {
            __u16 potential_class = 0;
            __u16 potential_method = 0;
            bpf_read(buf + 7, potential_class);
            bpf_read(buf + 9, potential_method);
            
            // Check for AMQP Basic class (60) and Publish method (40)
            if (bpf_htons(potential_class) == 60 && bpf_htons(potential_method) == 40) {
                return 0; // This looks like AMQP, not ClickHouse
            }
        }
    }
    
    return 1;
}

static __always_inline
int is_clickhouse_response(char *buf, __s32 *status) {
    __u8 code = 0;
    bpf_read(buf, code);
    if (code == CLICKHOUSE_SERVER_CODE_DATA || code == CLICKHOUSE_SERVER_CODE_END_OF_STREAM) {
        *status = STATUS_OK;
        return 1;
    }
    if (code == CLICKHOUSE_SERVER_CODE_EXCEPTION) {
        *status = STATUS_FAILED;
        return 1;
    }
    return 0;
}
