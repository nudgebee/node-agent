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
#define PROTOCOL_FOUNDATIONDB 16

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
    asm volatile ("%0 &= %1" : "+r"(size) : "i"(MAX_PAYLOAD_SIZE-1));   \
})

// COPY_PAYLOAD for use with non-ringbuf allocations (l7_request heap)
#define COPY_PAYLOAD(dst, size, src) ({     \
    TRUNCATE_PAYLOAD_SIZE(size);            \
    if (bpf_probe_read(dst, size, src)) {   \
        return 0;                           \
    }                                       \
})

// COPY_PAYLOAD_RINGBUF for use with ring buffer allocations
// Discards the event and returns 0 on failure to satisfy eBPF verifier
#define COPY_PAYLOAD_RINGBUF(e, dst, size, src) ({  \
    TRUNCATE_PAYLOAD_SIZE(size);                    \
    if (bpf_probe_read(dst, size, src)) {           \
        bpf_ringbuf_discard(e, 0);                  \
        return 0;                                   \
    }                                               \
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
#include "foundationdb.c"

// Include socket info extraction (must be before l7_event uses socket_tuple)
#include "../socket_info.c"

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
    // Socket tuple - extracted directly from fd, no TCP event dependency
    __u8 saddr[16];      // Source address (IPv4 in first 4 bytes, or full IPv6)
    __u8 daddr[16];      // Destination address
    __u16 sport;         // Source port
    __u16 dport;         // Destination port
    __u16 addr_family;   // AF_INET (2) or AF_INET6 (10)
    __u8 socket_info_valid;  // 1 if socket info was extracted
    __u8 padding2;
    char payload[MAX_PAYLOAD_SIZE];
    char response[MAX_PAYLOAD_SIZE];
};

struct iovec {
    char* buf;
    __u64 size;
};

// Ring buffer for L7 events - provides global ordering across CPUs
// Size: 8MB shared buffer (1 << 23 = 8388608 bytes)
// Benefits over perf buffer:
//   - Global event ordering (important for SSE streaming)
//   - More efficient memory usage (shared vs per-CPU)
//   - Backpressure via reserve/submit pattern
// Requires kernel 5.8+
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);  // 8MB
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

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__u64 msg_iovlen;
	void *msg_control;
    __u64 msg_controllen;
    __u32 msg_flags;
};

// send_event submits an L7 event to the ring buffer
// The event must have been allocated via bpf_ringbuf_reserve(&l7_events, ...)
static inline __attribute__((__always_inline__))
void send_event(void *ctx, struct l7_event *e, struct connection_id cid, struct connection *conn) {
    e->connection_timestamp = conn->timestamp;
    e->fd = cid.fd;
    e->pid = cid.pid;

    // Extract socket info directly from fd - no dependency on TCP events
    // This fixes Go goroutine thread-switching issues where TCP connection
    // tracking fails due to fd_by_pid_tgid lookup using different thread ID
    struct socket_tuple tuple = {};
    if (get_socket_tuple_from_fd((__u32)cid.fd, &tuple)) {
        __builtin_memcpy(e->saddr, tuple.saddr, sizeof(e->saddr));
        __builtin_memcpy(e->daddr, tuple.daddr, sizeof(e->daddr));
        e->sport = tuple.sport;
        e->dport = tuple.dport;
        e->addr_family = tuple.family;
        e->socket_info_valid = 1;
    } else {
        e->socket_info_valid = 0;
    }

    bpf_ringbuf_submit(e, 0);
}

// reserve_l7_event allocates an l7_event from the ring buffer
// Returns NULL if the ring buffer is full (backpressure)
static inline __attribute__((__always_inline__))
struct l7_event *reserve_l7_event(void) {
    struct l7_event *e = bpf_ringbuf_reserve(&l7_events, sizeof(struct l7_event), 0);
    if (e) {
        // Initialize event to zero state
        e->protocol = PROTOCOL_UNKNOWN;
        e->status = STATUS_UNKNOWN;
        e->method = METHOD_UNKNOWN;
        e->statement_id = 0;
        e->payload_size = 0;
        e->response_size = 0;
    }
    return e;
}

// discard_l7_event discards a reserved event without sending
// Use when an error occurs after reserve but before send
static inline __attribute__((__always_inline__))
void discard_l7_event(struct l7_event *e) {
    bpf_ringbuf_discard(e, 0);
}

static inline __attribute__((__always_inline__))
__u64 read_iovec(char *iovec, __u64 iovlen, __u64 ret, char *buf, __u64 *total_size) {
    if (iovlen == 0) {
        return 0;
    }
    
    // Only process the first iovec entry to avoid verifier issues with offset arithmetic
    struct iovec iov = {};
    if (bpf_probe_read(&iov, sizeof(iov), (void *)iovec)) {
        return 0;
    }
    
    if (iov.size <= 0) {
        return 0;
    }
    
    *total_size = iov.size;
    __u64 size = MIN(iov.size, MAX_PAYLOAD_SIZE);
    TRUNCATE_PAYLOAD_SIZE(size);
    
    // Direct copy without offset arithmetic on map values
    if (bpf_probe_read(buf, size, (void *)iov.buf)) {
        return 0;
    }
    
    return size;
}

static inline __attribute__((__always_inline__))
int trace_enter_write(void *ctx, __u64 fd, __u16 is_tls, char *buf, __u64 size, __u64 iovlen) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    // Debug: Log at entry to trace_enter_write for TLS
    if (is_tls) {
        bpf_printk("l7_ENTRY: pid=%u fd=%llu size=%llu", pid, fd, size);
    }

    __u32 zero = 0;
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;
    __u64 total_size = size;

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    struct connection conn_on_stack = {};

    if (!conn) {
        struct socket_tuple tuple = {};
        if (is_tls) {
            // For Go TLS, TCP tracking can fail. As a fallback, extract socket info directly.
            if (get_socket_tuple_from_fd((__u32)fd, &tuple)) {
                conn_on_stack.dport = tuple.dport;
                conn = &conn_on_stack;
                bpf_printk("l7_CONN_FALLBACK: pid=%u fd=%llu dport=%u", cid.pid, fd, conn->dport);
            }
        } else if (get_socket_tuple_from_fd((__u32)fd, &tuple) && tuple.dport == 53) {
            // UDP DNS: inet_sock_set_state only tracks TCP, so UDP sockets
            // are never in active_connections. Allow DNS through for ip2fqdn resolution.
            conn_on_stack.dport = 53;
            conn = &conn_on_stack;
        }
    }

    if (!conn) {
        // Log ALL TLS connection lookup failures (not just large payloads)
        if (is_tls) {
            bpf_printk("l7_NOT_FOUND: pid=%u fd=%llu size=%llu", cid.pid, fd, size);
        }
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
    req->protocol = conn->protocol; // Use the known protocol if it exists

    // Debug: Log TLS write with protocol info
    if (is_tls) {
        bpf_printk("l7_FOUND: pid=%u fd=%llu proto=%d", cid.pid, fd, conn->protocol);
    }
    req->partial = 0;
    req->request_id = 0;
    req->ns = 0;
    req->payload_size = size;
    struct l7_request_key k = {};
    k.pid = cid.pid;
    k.fd = cid.fd;
    k.is_tls = is_tls;
    k.stream_id = -1;

    // Fast path: If connection is already known to be HTTP/2, handle immediately
    if (req->protocol == PROTOCOL_HTTP2) {
        struct l7_event *e = reserve_l7_event();
        if (!e) {
            if (is_tls) { bpf_printk("l7_H2_RESERVE_FAIL: pid=%u fd=%llu", cid.pid, fd); }
            return 0;
        }
        e->protocol = PROTOCOL_HTTP2;
        e->method = METHOD_HTTP2_CLIENT_FRAMES;
        e->duration = bpf_ktime_get_ns();
        e->payload_size = size;
        COPY_PAYLOAD_RINGBUF(e, e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        if (is_tls) { bpf_printk("l7_H2_SENT: pid=%u fd=%llu size=%llu", cid.pid, fd, size); }
        return 0;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) { // Only detect protocol if it's not already known
        // Port-based HTTP/2 hint: Try HTTP/2 detection first for HTTPS traffic (port 443/8443)
        // Most modern HTTPS traffic uses HTTP/2, and this helps detect gRPC DATA frames
        // that don't have the connection preface
        if (conn->dport != 53 && is_likely_http2_port(conn->dport) && looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
            conn->protocol = PROTOCOL_HTTP2; // Cache for subsequent frames
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_CLIENT_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = size;
            COPY_PAYLOAD_RINGBUF(e, e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        }

        if (is_http_request(payload)) {
            req->protocol = PROTOCOL_HTTP;
        } else if (is_postgres_query(payload, size, &req->request_type)) {
            req->protocol = PROTOCOL_POSTGRES;
        } else if (is_redis_query(payload, size)) {
            req->protocol = PROTOCOL_REDIS;
        } else if (is_memcached_query(payload, size)) {
            req->protocol = PROTOCOL_MEMCACHED;
        } else if (is_mysql_query(payload, size, &req->request_type)) {
            req->protocol = PROTOCOL_MYSQL;
        } else if (is_mongo_query(payload, size)) {
            req->protocol = PROTOCOL_MONGO;
        } else if (is_rabbitmq_produce(payload, size)) {
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_RABBITMQ;
            e->method = METHOD_PRODUCE;
            send_event(ctx, e, cid, conn);
            return 0;
        } else if (nats_method(payload, size) == METHOD_PRODUCE) {
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_NATS;
            e->method = METHOD_PRODUCE;
            send_event(ctx, e, cid, conn);
            return 0;
        } else if (is_cassandra_request(payload, size, &k.stream_id)) {
            req->protocol = PROTOCOL_CASSANDRA;
        } else if (is_dns_request(payload, size, &k.stream_id)) {
            req->protocol = PROTOCOL_DNS;
        } else if (looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
            // HTTP/2 detected on non-standard port
            conn->protocol = PROTOCOL_HTTP2; // Cache for subsequent frames
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_CLIENT_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = size;
            COPY_PAYLOAD_RINGBUF(e, e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        } else if (conn->dport == 5672 && (is_rabbitmq_connection(payload, size) || is_amqp_frame(payload, size) || is_amqp_method_frame(payload, size))) {
            // Port-based hint: RabbitMQ typically runs on port 5672
            req->protocol = PROTOCOL_RABBITMQ;
        } else if ((conn->dport == 9000 || conn->dport == 8123) && is_clickhouse_query(payload, size)) {
            // Port-based hint: ClickHouse typically runs on ports 9000 (native) or 8123 (HTTP)
            req->protocol = PROTOCOL_CLICKHOUSE;
        } else if (is_rabbitmq_connection(payload, size)) {
            req->protocol = PROTOCOL_RABBITMQ;
        } else if (is_amqp_frame(payload, size)) {
            req->protocol = PROTOCOL_RABBITMQ;
        } else if (is_amqp_method_frame(payload, size)) {
            req->protocol = PROTOCOL_RABBITMQ;
        } else if (is_clickhouse_query(payload, size)) {
            req->protocol = PROTOCOL_CLICKHOUSE;
        } else if (is_zk_request(payload, total_size)) {
            req->protocol = PROTOCOL_ZOOKEEPER;
        }  else if (is_kafka_request(payload, size, &req->request_id)) {
            req->protocol = PROTOCOL_KAFKA;
        } else if (is_dubbo2_request(payload, size)) {
            req->protocol = PROTOCOL_DUBBO2;
        } else if (is_foundationdb_request(payload, size)) {
            req->protocol = PROTOCOL_FOUNDATIONDB;
        }
        if (req->protocol != PROTOCOL_UNKNOWN) {
            conn->protocol = req->protocol; // Save the detected protocol
        }
    }

    if (req->protocol == PROTOCOL_POSTGRES && req->request_type == POSTGRES_FRAME_CLOSE) {
        struct l7_event *e = reserve_l7_event();
        if (!e) { return 0; }
        e->protocol = PROTOCOL_POSTGRES;
        e->method = METHOD_STATEMENT_CLOSE;
        e->payload_size = size;
        COPY_PAYLOAD_RINGBUF(e, e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        return 0;
    }
    if (req->protocol == PROTOCOL_MYSQL && req->request_type == MYSQL_COM_STMT_CLOSE) {
        struct l7_event *e = reserve_l7_event();
        if (!e) { return 0; }
        e->protocol = PROTOCOL_MYSQL;
        e->method = METHOD_STATEMENT_CLOSE;
        e->payload_size = size;
        COPY_PAYLOAD_RINGBUF(e, e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        return 0;
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
        // UDP DNS: inet_sock_set_state only tracks TCP, so UDP sockets
        // are never in active_connections. Allow DNS reads through.
        struct socket_tuple tuple = {};
        if (!get_socket_tuple_from_fd((__u32)fd, &tuple) || tuple.dport != 53) {
            return 0;
        }
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
    struct connection conn_on_stack = {};
    if (!conn) {
        // UDP DNS: inet_sock_set_state only tracks TCP, so UDP sockets
        // are never in active_connections. Allow DNS responses through.
        struct socket_tuple tuple = {};
        if (get_socket_tuple_from_fd((__u32)cid.fd, &tuple) && tuple.dport == 53) {
            conn_on_stack.dport = 53;
            conn = &conn_on_stack;
        } else {
            bpf_map_delete_elem(&active_reads, &id);
            return 0;
        }
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
        // Skip iovec processing to avoid eBPF verifier issues
        return 0;
    }

    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_received, total_size);
    }

    struct l7_event *e = reserve_l7_event();
    if (!e) {
        return 0;
    }
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    e->statement_id = 0;
    e->payload_size = 0;

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

    // Fast path: If connection is already known to be HTTP/2, handle immediately
    if (conn->protocol == PROTOCOL_HTTP2) {
        e->protocol = PROTOCOL_HTTP2;
        e->method = METHOD_HTTP2_SERVER_FRAMES;
        e->duration = bpf_ktime_get_ns();
        e->payload_size = ret;
        COPY_PAYLOAD_RINGBUF(e, e->payload, ret, payload);
        send_event(ctx, e, cid, conn);
        return 0;
    }

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    int response = 0;
    if (!req) {
        if (is_dns_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                discard_l7_event(e);
                return 0;
            }
            e->protocol = PROTOCOL_DNS;
            e->duration = bpf_ktime_get_ns() - req->ns;
            e->payload_size = ret;
            COPY_PAYLOAD_RINGBUF(e, e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            bpf_map_delete_elem(&active_l7_requests, &k);
            return 0;
        } else if (is_cassandra_response(payload, ret, &k.stream_id, &e->status)) {
            req = bpf_map_lookup_elem(&active_l7_requests, &k);
            if (!req) {
                discard_l7_event(e);
                return 0;
            }
            response = 1;
        } else if (looks_like_http2_frame(payload, ret, METHOD_HTTP2_SERVER_FRAMES)) {
            // HTTP/2 detected - cache protocol for subsequent frames
            conn->protocol = PROTOCOL_HTTP2;
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = ret;
            COPY_PAYLOAD_RINGBUF(e, e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        } else {
            discard_l7_event(e);
            return 0;
        }
    }

    e->protocol = req->protocol;
    e->payload_size = req->payload_size;
    COPY_PAYLOAD_RINGBUF(e, e->payload, req->payload_size, req->payload);
    if (e->protocol == PROTOCOL_HTTP) {
        response = is_http_response(payload, &e->status);
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
            discard_l7_event(e);
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_KAFKA) {
        response = is_kafka_response(payload, req->request_id);
    } else if (e->protocol == PROTOCOL_CLICKHOUSE) {
        response = is_clickhouse_response(payload, &e->status);
        if (!response) {
            discard_l7_event(e);
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_ZOOKEEPER) {
        response = is_zk_response(payload, total_size, &e->status, req->partial);
        if (response == 2) { // partial
            req->partial = 1;
            discard_l7_event(e);
            return 0; // keeping the query in the map
        }
    } else if (e->protocol == PROTOCOL_DUBBO2) {
        response = is_dubbo2_response(payload, &e->status);
    } else if (e->protocol == PROTOCOL_FOUNDATIONDB) {
        response = is_foundationdb_response(payload, ret, &e->status);
        if (response == 2) { // partial
            discard_l7_event(e);
            return 0; // keeping the query in the map
        }
    }
    bpf_map_delete_elem(&active_l7_requests, &k);
    if (!response) {
        discard_l7_event(e);
        return 0;
    }
    e->duration = bpf_ktime_get_ns() - req->ns;
    e->response_size = ret;
    COPY_PAYLOAD_RINGBUF(e, e->response, ret, payload);
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
    if (ctx->size == 0) {
        return 0;
    }
    struct mmsghdr h = {};
    if (bpf_probe_read(&h , sizeof(h), (void *)ctx->buf)) {
        return 0;
    }
    return trace_enter_write(ctx, ctx->fd, 0, (char*)h.msg_hdr.msg_iov, 0, h.msg_hdr.msg_iovlen);
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
