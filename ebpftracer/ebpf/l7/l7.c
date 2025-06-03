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

#define L7_EVENT_FLAG_REQUEST_TRUNCATED  (1 << 0)
#define L7_EVENT_FLAG_RESPONSE_TRUNCATED (1 << 1)

#define TRUNCATE_PAYLOAD_SIZE(size) ({                                  \
    size = MIN(size, MAX_PAYLOAD_SIZE-1);                               \
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(MAX_PAYLOAD_SIZE-1));   \
})
#define COPY_PAYLOAD(dst, size, src) ({     \
    TRUNCATE_PAYLOAD_SIZE(size);            \
    if (bpf_probe_read(dst, size, src)) {   \
        return 0;                           \
    }                                       \
})

#define IOVEC_BUF_SIZE MAX_PAYLOAD_SIZE * 2  // must be double of MAX_PAYLOAD_SIZE
#define MAX_IOVEC_SIZE 32

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
    __u16 flags;
    __u32 statement_id;
    __u64 payload_size;
    __u64 response_size;
    char payload[MAX_PAYLOAD_SIZE];
    char response[MAX_PAYLOAD_SIZE];
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
    req->request_potentially_truncated = 0; // Initialize new field

    // total_size holds the original size before any potential truncation by read_iovec for payload analysis
    // size holds the size to be copied by COPY_PAYLOAD, potentially already limited by read_iovec's MAX_PAYLOAD_SIZE constraint for buffer
    req->request_potentially_truncated = (total_size >= MAX_PAYLOAD_SIZE);

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
            __builtin_memset(e, 0, sizeof(*e)); // Initialize event, including flags
            e->protocol = PROTOCOL_POSTGRES;
            e->method = METHOD_STATEMENT_CLOSE;
            if (total_size >= MAX_PAYLOAD_SIZE) {
                e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
            }
            __u64 copy_size = size; // size might be from read_iovec, total_size is original
            COPY_PAYLOAD(e->payload, copy_size, payload); // copy_size gets updated to truncated size
            e->payload_size = copy_size; // Store the actual copied size
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
            __builtin_memset(e, 0, sizeof(*e)); // Initialize event
            e->protocol = PROTOCOL_MYSQL;
            e->method = METHOD_STATEMENT_CLOSE;
            if (total_size >= MAX_PAYLOAD_SIZE) {
                e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
            }
            __u64 copy_size = size;
            COPY_PAYLOAD(e->payload, copy_size, payload); // copy_size gets updated
            e->payload_size = copy_size;
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
        __builtin_memset(e, 0, sizeof(*e));
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_PRODUCE;
        // Produce events often don't copy payload in this path, but if they did:
        // if (total_size >= MAX_PAYLOAD_SIZE) { e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED; }
        // e->payload_size = actual_copied_size;
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (nats_method(payload, size) == METHOD_PRODUCE) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        __builtin_memset(e, 0, sizeof(*e));
        e->protocol = PROTOCOL_NATS;
        e->method = METHOD_PRODUCE;
        // Similar to RabbitMQ produce
        // if (total_size >= MAX_PAYLOAD_SIZE) { e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED; }
        send_event(ctx, e, cid, conn);
        return 0;
    } else if (is_cassandra_request(payload, size, &k.stream_id)) {
        req->protocol = PROTOCOL_CASSANDRA;
    } else if (looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            return 0;
        }
        __builtin_memset(e, 0, sizeof(*e));
        e->protocol = PROTOCOL_HTTP2;
        e->method = METHOD_HTTP2_CLIENT_FRAMES;
        e->duration = bpf_ktime_get_ns(); // This is a timestamp of the event
        if (total_size >= MAX_PAYLOAD_SIZE) { // total_size is original frame size
            e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
        }
        __u64 copy_size = size; // size is from read_iovec or syscall
        COPY_PAYLOAD(e->payload, copy_size, payload); // copy_size gets updated
        e->payload_size = copy_size; // Store actual copied size
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
    // req->request_potentially_truncated is already set based on total_size
    // 'size' here is the size determined from read_iovec or original syscall size,
    // which is what COPY_PAYLOAD will attempt to copy.
    __u64 req_copy_size = size;
    COPY_PAYLOAD(req->payload, req_copy_size, payload); // req_copy_size gets updated
    req->payload_size = req_copy_size; // Store the actually copied (potentially truncated) size in req

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
    __builtin_memset(e, 0, sizeof(*e)); // Initialize event, including flags to 0
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    // e->payload_size will be filled from req if applicable

    // Handle response truncation
    // total_size is the original size of the data read by the syscall
    // ret is the amount of data successfully read into 'payload' buffer (potentially after read_iovec processing)
    if (total_size >= MAX_PAYLOAD_SIZE) {
        e->flags |= L7_EVENT_FLAG_RESPONSE_TRUNCATED;
    }
    __u64 response_copy_size = ret; // This 'ret' is the size available in 'payload' buffer
    COPY_PAYLOAD(e->response, response_copy_size, payload); // response_copy_size gets updated
    e->response_size = response_copy_size; // Store actual copied size

    // Check for consume events first as they don't rely on a prior request in active_l7_requests
    if (is_rabbitmq_consume(e->response, e->response_size)) {
        e->protocol = PROTOCOL_RABBITMQ;
        e->method = METHOD_CONSUME;
        // Request part is not applicable for consume, L7_EVENT_FLAG_REQUEST_TRUNCATED remains 0
        send_event(ctx, e, cid, conn);
        return 0;
    }
    if (nats_method(e->response, e->response_size) == METHOD_CONSUME) {
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
            if (req->request_potentially_truncated) {
                e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
            }
            // For DNS, the response is typically copied into e->payload.
            // The L7_EVENT_FLAG_RESPONSE_TRUNCATED set above for e->response might be misleading if e->response isn't sent.
            // Let's assume 'payload' (the read buffer) contains DNS response.
            // 'total_size' is original DNS response size. 'ret' is size in 'payload' buffer.
            // We are copying from 'payload' to 'e->payload'.
            e->flags &= ~L7_EVENT_FLAG_RESPONSE_TRUNCATED; // Clear general response flag, as DNS response goes to e->payload
            if (total_size >= MAX_PAYLOAD_SIZE) { // total_size is original size of DNS response
                e->flags |= L7_EVENT_FLAG_PAYLOAD_TRUNCATED_ALIAS; // Placeholder, this needs to be specific: e->payload is the response here
            }
            // Actually, let's simplify: if this is a DNS response, e->payload gets the response.
            // So L7_EVENT_FLAG_RESPONSE_TRUNCATED should apply to this copy.
             if (total_size >= MAX_PAYLOAD_SIZE) { // total_size is original size of DNS response in 'payload' buffer
                e->flags |= L7_EVENT_FLAG_RESPONSE_TRUNCATED;
            }
            __u64 dns_response_copy_size = ret; // ret is size of DNS response in 'payload'
            COPY_PAYLOAD(e->payload, dns_response_copy_size, payload); // dns_response_copy_size updated
            e->payload_size = dns_response_copy_size; // This is the DNS response size
            e->response_size = 0; // e->response is not used for DNS response

            e->protocol = PROTOCOL_DNS;
            e->duration = bpf_ktime_get_ns() - req->ns;
            // e->status is set by is_dns_response
            send_event(ctx, e, cid, conn);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        } else if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                return 0;
            }
            response = 1; // Mark that we found a matching request
            if (req->request_potentially_truncated) {
                e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
            }
            // Response truncation for e->response already handled by general logic.
            // For Cassandra, e->response contains the actual response.
        } else if (looks_like_http2_frame(e->response, e->response_size, METHOD_HTTP2_SERVER_FRAMES)) {
            // This is an HTTP2 server frame, not necessarily a direct response to a stored req.
            // Treated as a separate event. The content is in e->response.
            // The L7_EVENT_FLAG_RESPONSE_TRUNCATED on e->response is already set if it was truncated.
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = bpf_ktime_get_ns(); // Timestamp of the frame event
            // Request part is not applicable here.
            // e->payload is not used for these frames.
            e->payload_size = 0;
            send_event(ctx, e, cid, conn);
            return 0;
        } else {
            return 0; // No matching request or recognized standalone event
        }
    } else { // req was found for protocols other than DNS/Cassandra special handling above
        if (req->request_potentially_truncated) {
            e->flags |= L7_EVENT_FLAG_REQUEST_TRUNCATED;
        }
        // Copy request from req->payload to e->payload
        __u64 event_req_copy_size = req->payload_size; // req->payload_size is already truncated size
        COPY_PAYLOAD(e->payload, event_req_copy_size, req->payload);
        e->payload_size = event_req_copy_size; // Store it
    }

    // This part is for events that had a matching 'req'
    e->protocol = req->protocol; // Ensure protocol is from 'req'
    // e->response and e->response_size are already populated and truncation flagged.
    // e->payload and e->payload_size are populated from 'req' and truncation flagged.

    // Determine response type and status based on e->response (the current read buffer)
    if (e->protocol == PROTOCOL_HTTP) {
        response = is_http_response(e->response, e->response_size, &e->status);
    } else if (e->protocol == PROTOCOL_POSTGRES) {
        response = is_postgres_response(e->response, e->response_size, &e->status);
        if (req->request_type == POSTGRES_FRAME_PARSE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_REDIS) {
        response = is_redis_response(e->response, e->response_size, &e->status);
    } else if (e->protocol == PROTOCOL_MEMCACHED) {
        response = is_memcached_response(e->response, e->response_size, &e->status);
    } else if (e->protocol == PROTOCOL_MYSQL) {
        response = is_mysql_response(e->response, e->response_size, req->request_type, &e->statement_id, &e->status);
        if (req->request_type == MYSQL_COM_STMT_PREPARE) {
            e->method = METHOD_STATEMENT_PREPARE;
        }
    } else if (e->protocol == PROTOCOL_MONGO) {
        response = is_mongo_response(e->response, e->response_size, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        response = is_kafka_response(e->response, req->request_id); // Uses e->response content
    } else if (e->protocol == PROTOCOL_CLICKHOUSE) {
        response = is_clickhouse_response(e->response, &e->status); // Uses e->response content
        if (!response) {
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_ZOOKEEPER) {
        // For ZK, the original total_size of the response matters for is_zk_response logic
        response = is_zk_response(e->response, total_size, &e->status, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        response = is_dubbo2_response(e->response, &e->status); // Uses e->response content
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
