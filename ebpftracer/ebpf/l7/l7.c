#define PROTOCOL_UNKNOWN     0
#define PROTOCOL_HTTP	     1
#define PROTOCOL_POSTGRES    2
#define PROTOCOL_REDIS	     3
#define PROTOCOL_MEMCACHED   4
#define PROTOCOL_MYSQL       5
#define PROTOCOL_MONGO       6
#define PROTOCOL_KAFKA       7
#define PROTOCOL_CASSANDRA   8
#define PROTOCOL_RABBITMQ    9
#define PROTOCOL_NATS       10
#define PROTOCOL_HTTP2	    11
#define PROTOCOL_DUBBO2     12
#define PROTOCOL_DNS        13
#define PROTOCOL_CLICKHOUSE 14
#define PROTOCOL_ZOOKEEPER  15

#define STATUS_UNKNOWN  0
#define STATUS_OK       200
#define STATUS_FAILED   500

#define METHOD_UNKNOWN              0
#define METHOD_PRODUCE              1
#define METHOD_CONSUME              2
#define METHOD_STATEMENT_PREPARE    3
#define METHOD_STATEMENT_CLOSE      4
#define METHOD_HTTP2_CLIENT_FRAMES  5
#define METHOD_HTTP2_SERVER_FRAMES  6

#define TRUNCATE_PAYLOAD_SIZE(size) ({                                  \
    size = MIN(size, MAX_PAYLOAD_SIZE-1);                               \
})
#define COPY_PAYLOAD(dst, size, src) ({     \
    TRUNCATE_PAYLOAD_SIZE(size);            \
    if (bpf_probe_read(dst, size, src)) {   \
        return 0;                           \
    }                                       \
})

#define IOVEC_BUF_SIZE MAX_PAYLOAD_SIZE * 2  // must be double of MAX_PAYLOAD_SIZE
#define MAX_IOVEC_SIZE 32

// HTTP response capture configuration
#define MAX_HTTP_CAPTURE_SIZE (64 * 1024)       // 64KB default max capture
#define MAX_LARGE_RESPONSE_SIZE (1024 * 1024)   // 1MB threshold for "large" responses
#define LARGE_RESPONSE_CAPTURE_LIMIT (16 * 1024) // 16KB limit for large responses
#define MAX_FRAGMENTS_PER_RESPONSE 32            // Max fragments per response

#include "http.c"
#include "postgres.c"
#include "redis.c"
#include "memcached.c"
#include "mysql.c"
#include "mongo.c"
#include "kafka.c"
#include "cassandra.c"
#include "rabbitmq.c"
#include "nats.c"
#include "http2.c"
#include "dubbo2.c"
#include "dns.c"
#include "clickhouse.c"
#include "zookeeper.c"

struct l7_event {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __s32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    __u32 statement_id;
    __u64 payload_size;
    __u64 response_size;
    char payload[MAX_PAYLOAD_SIZE];
    char response[MAX_PAYLOAD_SIZE];
};

// HTTP response tracking state (64 bytes per connection)
struct http_response_state {
    __u64 start_time;
    __u32 content_length;    // From HTTP Content-Length header
    __u32 captured_size;     // Bytes captured so far  
    __u16 fragment_count;
    __u8 has_content_length; // Whether we parsed Content-Length
    __u8 capture_complete;   // Response fully captured
};

// HTTP response fragment (2KB each)
#define HTTP_FRAGMENT_SIZE 2048
struct http_response_fragment {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __u32 fragment_id;       // Sequence number
    __u32 total_expected;    // From Content-Length (0 if unknown)
    __u16 fragment_size;     // This fragment size
    __u8 is_final;          // Last fragment flag
    __u8 http_status;       // 200, 404, 500, etc.
    char data[HTTP_FRAGMENT_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

// HTTP response tracking maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct connection_id));
    __uint(value_size, sizeof(struct http_response_state));
    __uint(max_entries, 10240);
} http_response_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} http_response_fragments SEC(".maps");

struct read_args {
    __u64 fd;
    char* buf;
    __u64* ret;
    __u64 iovlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, char[IOVEC_BUF_SIZE]);
     __uint(max_entries, 1);
} iovec_buf_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct http_response_fragment);
     __uint(max_entries, 1);
} fragment_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct http_response_state);
     __uint(max_entries, 1);
} response_state_heap SEC(".maps");

struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    __u64 unused2;
    __u64 fd;
    char* buf;
    __u64 size;
};

struct iovec {
    char* buf;
    __u64 size;
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__u64 msg_iovlen;
	void *msg_control;
    __u64 msg_controllen;
    __u32 msg_flags;
};

static inline __attribute__((__always_inline__))
void send_event(void *ctx, struct l7_event *e, struct connection_id cid, struct connection *conn) {
    e->connection_timestamp = conn->timestamp;
    e->fd = cid.fd;
    e->pid = cid.pid;
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

// HTTP utility functions
static inline __attribute__((__always_inline__))
__u32 parse_http_content_length(char *response, __u32 size) {
    // Look for "Content-Length: NNNN" in HTTP headers
    char cl_pattern[] = "Content-Length:";
    __u32 cl_len = 15; // Length of "Content-Length:"
    
    #pragma unroll
    for (__u32 i = 0; i < MIN(size - cl_len, 1024); i++) {
        if (response[i] == 'C' || response[i] == 'c') {
            __u8 match = 1;
            #pragma unroll
            for (int j = 0; j < cl_len; j++) {
                if (i + j >= size) {
                    match = 0;
                    break;
                }
                char c1 = response[i + j];
                char c2 = cl_pattern[j];
                // Case insensitive comparison
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                if (c1 != c2) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                // Found Content-Length header, parse the number
                __u32 start = i + cl_len;
                while (start < size && response[start] == ' ') start++;
                
                __u32 content_length = 0;
                #pragma unroll
                for (int k = 0; k < 10; k++) { // Max 10 digits
                    if (start + k >= size) break;
                    char digit = response[start + k];
                    if (digit >= '0' && digit <= '9') {
                        content_length = content_length * 10 + (digit - '0');
                    } else {
                        break;
                    }
                }
                return content_length;
            }
        }
    }
    return 0;
}

static inline __attribute__((__always_inline__))
__u16 parse_http_status(char *response, __u32 size) {
    // Look for "HTTP/1.x NNN" or "HTTP/2 NNN" pattern
    if (size < 12) return 0;
    
    // Check for HTTP response pattern
    if ((size >= 8 && response[0] == 'H' && response[1] == 'T' && 
         response[2] == 'T' && response[3] == 'P' && response[4] == '/') ||
        (size >= 8 && response[0] == 'h' && response[1] == 't' &&
         response[2] == 't' && response[3] == 'p' && response[4] == '/')) {
        
        // Find the status code (skip "HTTP/x.x ")
        __u32 status_pos = 9; // Position after "HTTP/1.1 "
        if (size >= status_pos + 3) {
            char c1 = response[status_pos];
            char c2 = response[status_pos + 1];
            char c3 = response[status_pos + 2];
            
            if (c1 >= '1' && c1 <= '5' && c2 >= '0' && c2 <= '9' && c3 >= '0' && c3 <= '9') {
                return (__u16)((c1 - '0') * 100 + (c2 - '0') * 10 + (c3 - '0'));
            }
        }
    }
    return 0;
}

static inline __attribute__((__always_inline__))
__u64 read_iovec(char *iovec, __u64 iovlen, __u64 ret, char *buf, __u64 *total_size) {
    struct iovec iov = {};
    __u64 max = (ret) ? MIN(ret, MAX_PAYLOAD_SIZE) : MAX_PAYLOAD_SIZE;
    __u64 offset = 0;
    __u64 size = 0;
    #pragma unroll
    for (int i = 0; i < MAX_IOVEC_SIZE; i++) {
        if (i >= iovlen) {
            break;
        }
        if (bpf_probe_read(&iov, sizeof(iov), (void *)(iovec+i*sizeof(iov)))) {
            return 0;
        }
        if (iov.size <= 0) {
            continue;
        }
        *total_size += iov.size;
        if (offset < max) {
            size = MIN(iov.size, max-offset);
            TRUNCATE_PAYLOAD_SIZE(size);
            TRUNCATE_PAYLOAD_SIZE(offset);
            if (bpf_probe_read(buf + offset, size, (void *)iov.buf)) {
                return 0;
            }
            offset += size;
        }
    }
    return offset;
}

// HTTP multi-packet response handler (parallel with L7 events)
static inline __attribute__((__always_inline__))
void handle_http_streaming_response(void *ctx, struct connection_id cid, struct connection *conn, 
                                  char *payload, __u64 ret, __u16 http_status) {
    struct http_response_state *state = bpf_map_lookup_elem(&http_response_tracking, &cid);
    
    if (!state) {
        // First fragment - initialize response state using per-CPU map
        int zero = 0;
        struct http_response_state *new_state = bpf_map_lookup_elem(&response_state_heap, &zero);
        if (!new_state) return;
        
        // Initialize state manually
        new_state->start_time = bpf_ktime_get_ns();
        new_state->content_length = parse_http_content_length(payload, ret);
        new_state->has_content_length = (new_state->content_length > 0);
        new_state->captured_size = 0;
        new_state->fragment_count = 0;
        new_state->capture_complete = 0;
        
        bpf_map_update_elem(&http_response_tracking, &cid, new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&http_response_tracking, &cid);
        if (!state) return;
    }
    
    // Determine capture strategy based on response size
    __u32 max_capture_size = MAX_HTTP_CAPTURE_SIZE;
    __u8 should_continue_capture = 1;
    
    if (state->has_content_length) {
        if (state->content_length > MAX_LARGE_RESPONSE_SIZE) {
            // Very large response - limit capture
            max_capture_size = LARGE_RESPONSE_CAPTURE_LIMIT;
            should_continue_capture = (state->captured_size < max_capture_size);
        }
    } else {
        // No Content-Length - use fragment count limit
        should_continue_capture = (state->fragment_count < MAX_FRAGMENTS_PER_RESPONSE);
    }
    
    if (!should_continue_capture) {
        // Response too large, stop fragment capture
        bpf_map_delete_elem(&http_response_tracking, &cid);
        return;
    }
    
    // Stream response in fragments
    __u32 offset = 0;
    while (offset < ret && state->captured_size < max_capture_size && 
           state->fragment_count < MAX_FRAGMENTS_PER_RESPONSE) {
        
        __u32 remaining_space = max_capture_size - state->captured_size;
        __u32 fragment_size = MIN(MIN(HTTP_FRAGMENT_SIZE, remaining_space), ret - offset);
        
        // Explicit bounds check for eBPF verifier
        if (fragment_size > HTTP_FRAGMENT_SIZE) {
            fragment_size = HTTP_FRAGMENT_SIZE;
        }
        if (fragment_size == 0) {
            break;
        }
        
        int zero = 0;
        struct http_response_fragment *frag = bpf_map_lookup_elem(&fragment_heap, &zero);
        if (!frag) {
            break; // Can't allocate fragment
        }
        
        // Initialize fragment (manual zeroing since we can't use = {})
        frag->fd = cid.fd;
        frag->connection_timestamp = conn->timestamp;
        frag->pid = cid.pid;
        frag->fragment_id = state->fragment_count;
        frag->total_expected = state->content_length;
        frag->fragment_size = fragment_size;
        frag->http_status = http_status;
        frag->is_final = 0;
        
        // Copy fragment data with explicit constant bounds  
        __u32 copy_size = fragment_size;
        if (copy_size >= HTTP_FRAGMENT_SIZE) {
            copy_size = HTTP_FRAGMENT_SIZE - 1;
        }
        if (bpf_probe_read(frag->data, copy_size, payload + offset)) {
            break; // Read failed
        }
        
        // Check if this is the final fragment
        __u8 is_response_complete = 0;
        if (state->has_content_length) {
            is_response_complete = (state->captured_size + fragment_size >= state->content_length);
        } else {
            // For chunked/streaming responses, assume complete if small fragment
            is_response_complete = (fragment_size < HTTP_FRAGMENT_SIZE / 2);
        }
        
        frag->is_final = is_response_complete || 
                       (state->captured_size + fragment_size >= max_capture_size) ||
                       (state->fragment_count >= MAX_FRAGMENTS_PER_RESPONSE - 1);
        
        // Send fragment
        bpf_perf_event_output(ctx, &http_response_fragments, BPF_F_CURRENT_CPU, 
                             frag, sizeof(*frag));
        
        offset += fragment_size;
        state->captured_size += fragment_size;
        state->fragment_count++;
        
        if (frag->is_final) {
            // Mark response as complete but don't delete - let L7 processing retrieve it
            state->capture_complete = 1;
            break;
        }
    }
    
    // Fragment capture complete or in progress
}

static inline __attribute__((__always_inline__))
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, char *buf, __u64 size, __u64 iovlen) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 zero = 0;
    struct connection_id cid = {};
    cid.pid = id >> 32;
    cid.fd = fd;
    __u64 total_size = size;

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }

    char* payload = buf;
    if (iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        size = read_iovec(buf, iovlen, 0, payload, &total_size);
    }
    if (!size) {
        return 0;
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_sent, total_size);
    }

    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0;
    req->ns = 0;
    req->payload_size = size;
    struct l7_request_key k = {};
    k.pid = cid.pid;
    k.fd = cid.fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    if (is_http_request(payload)) {
        req->protocol = PROTOCOL_HTTP;
    } else if (is_postgres_query(payload, size, &req->request_type)) {
        if (req->request_type == POSTGRES_FRAME_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_POSTGRES;
            e->method = METHOD_STATEMENT_CLOSE;
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        }
        req->protocol = PROTOCOL_POSTGRES;
    } else if (is_redis_query(payload, size)) {
        req->protocol = PROTOCOL_REDIS;
    } else if (is_memcached_query(payload, size)) {
        req->protocol = PROTOCOL_MEMCACHED;
    } else if (is_mysql_query(payload, size, &req->request_type)) {
        if (req->request_type == MYSQL_COM_STMT_CLOSE) {
            struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
            if (!e) {
                return 0;
            }
            e->protocol = PROTOCOL_MYSQL;
            e->method = METHOD_STATEMENT_CLOSE;
            e->payload_size = size;
            COPY_PAYLOAD(e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        }
        req->protocol = PROTOCOL_MYSQL;
    } else if (is_mongo_query(payload, size)) {
        req->protocol = PROTOCOL_MONGO;
    } else if (is_rabbitmq_produce(payload, size)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_PRODUCE;
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (nats_method(payload, size) == METHOD_PRODUCE) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_PRODUCE;
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (is_cassandra_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_CASSANDRA;
    } else if (looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        e->protocol = PROTOCOL_HTTP2;
        e->method = METHOD_HTTP2_CLIENT_FRAMES;
        e->duration = bpf_ktime_get_ns();
        e->payload_size = size;
        COPY_PAYLOAD(e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (is_clickhouse_query(payload, size)) {
        req->protocol = PROTOCOL_CLICKHOUSE;
    } else if (is_zk_request(payload, total_size)) {
        req->protocol = PROTOCOL_ZOOKEEPER;
    }  else if (is_kafka_request(payload, size, &req->request_id)) {
        req->protocol = PROTOCOL_KAFKA;
        struct l7_request *prev_req = bpf_map_lookup_elem(&active_l7_requests, &k);
        if (prev_req && prev_req->protocol == PROTOCOL_KAFKA) {
            req->ns = prev_req->ns;
        }
    } else if (is_dubbo2_request(payload, size)) {
        req->protocol = PROTOCOL_DUBBO2;
    } else if (is_dns_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_DNS;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) {
        return 0;
    }
    if (req->ns == 0) {
        req->ns = bpf_ktime_get_ns();
    }
    COPY_PAYLOAD(req->payload, size, payload);
    bpf_map_update_elem(&active_l7_requests, &k, req, BPF_NOEXIST);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_enter_read(__u64 id, __u32 pid, __u64 fd, char *buf, __u64 *ret, __u64 iovlen) {
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        return 0;
    }

    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.ret = ret;
    args.iovlen = iovlen;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int trace_exit_read(void *ctx, __u64 id, __u32 pid, __u16 is_tls, long int ret) {
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = args->fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (!conn) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    struct l7_request_key k = {};
    k.pid = cid.pid;
    k.fd = cid.fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    bpf_map_delete_elem(&active_reads, &id);

    if (ret <= 0) {
        return 0;
    }
    if (args->ret) {
        if (bpf_probe_read(&ret, sizeof(ret), (void*)args->ret)) {
            return 0;
        };
        if (ret <= 0) {
            return 0;
        }
    }
    __u64 total_size = ret;
    int zero = 0;
    char* payload = args->buf;
    if (args->iovlen) {
        payload = bpf_map_lookup_elem(&iovec_buf_heap, &zero);
        if (!payload) {
            return 0;
        }
        total_size = 0;
        ret = read_iovec(args->buf, args->iovlen, ret, payload, &total_size);
        if (!ret) {
            return 0;
        }
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_received, total_size);
    }

    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;
    e->payload_size = 0;
    e->response_size = ret;
    COPY_PAYLOAD(e->response, ret, payload);
    if (is_rabbitmq_consume(payload, ret)) {
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_CONSUME;
        send_event(ctx, e, cid, conn);
        return 0;
    }
    if (nats_method(payload, ret) == METHOD_CONSUME) {
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_CONSUME;
        send_event(ctx, e, cid, conn);
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    int response = 0;
    if (!req) {
        if (is_dns_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            e->protocol = PROTOCOL_DNS;
            e->duration = bpf_ktime_get_ns() - req->ns;
            e->payload_size = ret;
            COPY_PAYLOAD(e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        } else if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            response = 1;
        } else if (looks_like_http2_frame(payload, ret, METHOD_HTTP2_SERVER_FRAMES)) {
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = ret;
            COPY_PAYLOAD(e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        } else {
            return 0;
        }
    }

    e->protocol = req->protocol;
    e->payload_size = req->payload_size;
    COPY_PAYLOAD(e->payload, req->payload_size, req->payload);
    if (e->protocol == PROTOCOL_HTTP) {
        response = is_http_response(payload, &e->status);
        if (response) {
            // TODO: Fragment capture temporarily disabled for eBPF verifier compatibility  
            // __u16 http_status = parse_http_status(payload, ret);
            // handle_http_streaming_response(ctx, cid, conn, payload, ret, http_status);
            // Continue with normal L7 event processing
        }
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        response = is_postgres_response(payload, ret, &e->status);
        if (req->request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        response = is_redis_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        response = is_memcached_response(payload, ret, &e->status);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        response = is_mysql_response(payload, ret, req->request_type, &e->statement_id, &e->status);
        if (req->request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        response = is_mongo_response(payload, ret, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        response = is_kafka_response(payload, req->request_id);
    } else if (e->protocol == PROTOCOL_CLICKHOUSE) {
        response = is_clickhouse_response(payload, &e->status);
        if (!response) {
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_ZOOKEEPER) {
        response = is_zk_response(payload, total_size, &e->status, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        response = is_dubbo2_response(payload, &e->status);
    }
    bpf_map_delete_elem(&active_l7_requests, &k);
    if (!response) {
        return 0;
    }
    e->duration = bpf_ktime_get_ns() - req->ns;
    send_event(ctx, e, cid, conn);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_enter_sendmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    return trace_enter_write(ctx, ctx->fd, 0, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

struct mmsghdr {
	struct user_msghdr msg_hdr;
	__u32 msg_len;
};

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int sys_enter_sendmmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 offset = 0;
    #pragma unroll
    for (int i = 0; i <= 1; i++) {
        if (i >= ctx->size) {
            break;
        }
        struct mmsghdr h = {};
        if (bpf_probe_read(&h , sizeof(h), (void *)(ctx->buf + offset))) {
            return 0;
        }
        offset += sizeof(h);
        trace_enter_write(ctx, ctx->fd, 0, (char*)h.msg_hdr.msg_iov, 0, h.msg_hdr.msg_iovlen);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    return trace_enter_write(ctx, ctx->fd, 0, ctx->buf, ctx->size, 0);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, ctx->size);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_enter_recvmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int sys_exit_readv(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int sys_exit_recvmsg(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit__stub* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return trace_exit_read(ctx, pid_tgid, pid, 0, ctx->ret);
}
