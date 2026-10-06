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
#define PROTOCOL_TLS_CLIENTHELLO 17

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

// TRUNCATE_COPY_SIZE bounds a copy into a MAX_PAYLOAD_SIZE buffer (an
// event's payload or response, a request's payload) to the whole buffer.
// TRUNCATE_PAYLOAD_SIZE stops one byte short, while payload_size and
// userspace allow MAX_PAYLOAD_SIZE: a 4096-byte write, which is how Go's
// HTTP/2 flushes its 4 KB write buffer, was decoded with a last byte the
// event never wrote, inside whichever frame crossed the end of the buffer.
//
// The clamp is asm so the verifier sees the compare on the register the copy
// uses: written in C, clang compared a copy and the verifier lost the bound.
#define TRUNCATE_COPY_SIZE(size) ({                                         \
    asm volatile ("if %0 <= %1 goto +1\n\t%0 = %1"                          \
                  : "+r"(size) : "i"(MAX_PAYLOAD_SIZE));                     \
})

// COPY_PAYLOAD for use with non-ringbuf allocations (l7_request heap)
#define COPY_PAYLOAD(dst, size, src) ({     \
    TRUNCATE_COPY_SIZE(size);               \
    if (bpf_probe_read(dst, size, src)) {   \
        return 0;                           \
    }                                       \
})

// connection.l7_lost bits: events lost on the written and read side.
#define L7_LOST_WRITES 1
#define L7_LOST_READS  2

// COPY_PAYLOAD_RINGBUF copies a payload into an event from reserve_l7_event.
// If the read fails the event is dropped (returns 0), and the loss is
// recorded on the connection as send_event records a full ring buffer, so a
// stateful parser learns of the gap.
#define COPY_PAYLOAD_RINGBUF(conn, lost, dst, size, src) ({     \
    TRUNCATE_COPY_SIZE(size);                                   \
    if (bpf_probe_read(dst, size, src)) {                       \
        (conn)->l7_lost |= (lost);                              \
        return 0;                                               \
    }                                                           \
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
#include "sni.c"

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
    __u8 is_tls;  // payload came from a TLS library hook, i.e. it is plaintext
    __u8 lost_before; // connection.l7_lost when this event was sent
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
    __uint(max_entries, 1 << 25);  // 32MB — prevents event drops on busy nodes
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

// OpenSSL plaintext is tied to its connection by the socket syscalls made on
// the same thread, never by reading the fd out of the SSL/BIO structs. That
// only ever worked for a socket BIO, at struct offsets that differ between
// OpenSSL releases, so it silently lost every OpenSSL 3.0/3.1 process, curl
// (its own BIO, num=0) and .NET (memory BIOs, num=-1).
//
// SSL_write/SSL_read park their arguments in ssl_write_pending/ssl_read_pending
// keyed by thread; the next socket write/read on that thread supplies the fd,
// which is then remembered per SSL object in ssl_fds. A memory BIO application
// reads ciphertext itself *before* calling SSL_read, so its reads can only be
// resolved through ssl_fds, learned from the request it wrote first.
struct ssl_args {
    char *buf;
    __u64 size;
    __u64 *ret;  // SSL_read_ex: out-param holding the bytes read
    __u64 ssl;   // SSL*, keys ssl_fds
    __u64 fd;    // reads: the socket read inside SSL_read, 0 if none
    __u64 ns;    // writes: when SSL_write was entered
};

struct ssl_key {
    __u64 ssl;
    __u32 pid;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, 10240);
} ssl_write_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct ssl_args));
    __uint(max_entries, 10240);
} ssl_read_pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct ssl_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 32768);
} ssl_fds SEC(".maps");

// A pending SSL_write is claimed by a socket write on the same thread within
// this window. With a socket BIO that write happens inside SSL_write; with a
// memory BIO the application sends the ciphertext right after SSL_write
// returns. Anything later is too weak a correlation to attribute plaintext on.
#define SSL_PENDING_WRITE_TTL_NS 100000000ULL

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

// l7_ringbuf_drops counts L7 events lost because l7_events was full.
// Userspace exports it as node_agent_l7_ringbuf_drops_total.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} l7_ringbuf_drops SEC(".maps");

// L7_EVENT_LEN_MASK is the smallest all-ones mask covering sizeof(struct
// l7_event); send_event uses it to bound the record length for the verifier.
#define L7_EVENT_LEN_MASK 0x3fff

// l7_event_heap is where an event is built before it is copied into
// l7_events at its actual size (see send_event).
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, int);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

// send_event copies an L7 event built by reserve_l7_event into the ring
// buffer, sized to what it carries. Records used to be reserved at the full
// struct size, two MAX_PAYLOAD_SIZE buffers whatever the payload, so a burst
// of small events (HTTP/2 frames of a streaming response) filled the buffer
// with mostly empty slots and later events were lost. Payload and response
// stay at their fixed offsets, so userspace decodes either size the same way.
static inline __attribute__((__always_inline__))
void send_event(void *ctx, struct l7_event *e, struct connection_id cid, struct connection *conn) {
    e->connection_timestamp = conn->timestamp;
    e->fd = cid.fd;
    e->pid = cid.pid;
    // Socket-level events on TLS-marked connections are dropped before they
    // get here, so on such a connection every event carries plaintext.
    e->is_tls = conn->tls;

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

    __u64 data = e->response_size ? e->response_size : e->payload_size;
    if (data > MAX_PAYLOAD_SIZE) {
        data = MAX_PAYLOAD_SIZE;
    }
    __u64 len = (e->response_size ? __builtin_offsetof(struct l7_event, response)
                                  : __builtin_offsetof(struct l7_event, payload)) + data;
    // Bound len for the verifier: the mask makes it non-negative and small,
    // the comparison caps it at the event's size.
    asm volatile ("%0 &= %1" : "+r"(len) : "i"(L7_EVENT_LEN_MASK));
    if (len > sizeof(struct l7_event)) {
        len = sizeof(struct l7_event);
    }
    // A record with a response carries the whole payload buffer, so the bytes
    // between payload_size and MAX_PAYLOAD_SIZE are left over from an earlier
    // event on this CPU. They are plaintext the agent already received, the
    // ring is readable only by the agent, and the decoder copies exactly
    // payload_size bytes; zeroing 4 KB per event would cost more than it buys.
    //
    // A lost event leaves a gap in its connection's stream that a stateful
    // parser cannot see on its own: HTTP/2 frames are cut mid-way and the
    // HPACK table misses insertions, so later headers decode to wrong values.
    // Record the loss on the connection and hand it to the next event that is
    // delivered. The read-modify-write is not atomic (atomic OR needs 5.12);
    // two CPUs racing on one connection can lose a flag, rarely.
    e->lost_before = conn->l7_lost;
    if (bpf_ringbuf_output(&l7_events, e, len, 0)) {
        __u32 zero = 0;
        __u64 *drops = bpf_map_lookup_elem(&l7_ringbuf_drops, &zero);
        if (drops) {
            *drops += 1;
        }
        conn->l7_lost |= e->method == METHOD_HTTP2_SERVER_FRAMES ? L7_LOST_READS : L7_LOST_WRITES;
    } else if (e->lost_before) {
        conn->l7_lost = 0;
    }
}

// reserve_l7_event returns this CPU's scratch event, with its header reset.
// Nothing is taken from the ring buffer until send_event, so an event that is
// built and then dropped (most reads turn out not to need one) costs no ring
// space.
static inline __attribute__((__always_inline__))
struct l7_event *reserve_l7_event(void) {
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }
    __builtin_memset(e, 0, __builtin_offsetof(struct l7_event, payload));
    e->protocol = PROTOCOL_UNKNOWN;
    e->status = STATUS_UNKNOWN;
    e->method = METHOD_UNKNOWN;
    return e;
}

// discard_l7_event drops an event from reserve_l7_event without sending it.
// The scratch buffer needs no release; this marks where an event is dropped.
static inline __attribute__((__always_inline__))
void discard_l7_event(struct l7_event *e) {
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
    __u64 size = iov.size;
    TRUNCATE_COPY_SIZE(size);
    
    // Direct copy without offset arithmetic on map values
    if (bpf_probe_read(buf, size, (void *)iov.buf)) {
        return 0;
    }
    
    return size;
}

// http2_detection_window bounds where the weak frame-shape heuristic may run.
//
// looks_like_http2_frame accepts arbitrary binary data as HTTP/2 roughly once
// every 9k buffers: it requires only frame_type <= 9, a clear reserved bit, a
// HEADERS type byte and one HPACK byte with static index 1-14. That rate is
// survivable on its own, but conn->protocol is cached for the life of the
// connection, so a single false positive converts every later event on that
// connection into an HTTP/2 event permanently.
//
// A large binary transfer over HTTPS/1.1 (image layers, S3 objects) performs
// tens of thousands of reads, making a false positive near-certain, which is
// how HTTP/1.1 connections end up feeding garbage to the HPACK decoder.
//
// Real HTTP/2 announces itself immediately — client preface, then SETTINGS on
// stream 0 — so the heuristic only needs to run early. Past this many bytes a
// connection that has not already been identified is left alone. Connections
// joined mid-stream are lost either way: their HPACK dynamic table state is
// unrecoverable, so today they are "detected" only to produce undecodable
// garbage.
#define HTTP2_DETECTION_WINDOW_BYTES 65536

// tls_ciphertext_skipped counts socket-level events dropped by mark_tls'
// rule, per direction (0 = write, 1 = read). Userspace exports the sum as
// node_agent_l7_tls_ciphertext_skipped_total.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 2);
} tls_ciphertext_skipped SEC(".maps");

static inline __attribute__((__always_inline__))
void count_ciphertext_skip(__u32 direction) {
    __u64 *v = bpf_map_lookup_elem(&tls_ciphertext_skipped, &direction);
    if (v) {
        *v += 1;
    }
}

// tls_plaintext_dropped counts TLS plaintext a library hook saw but could not
// attribute to a socket, so it never left the kernel. Without it these losses
// were visible only through bpf_printk in a debug build. Userspace exports it
// as node_agent_tls_plaintext_dropped_total{reason}; the indexes must match
// tlsDropReasons in tracer.go.
#define TLS_DROP_GO_FD_UNKNOWN       0 // Go crypto/tls call whose socket fd could not be read; includes in-memory conns (net.Pipe, bufconn)
#define TLS_DROP_SSL_READ_FD_UNKNOWN 1 // SSL_read returned data, its socket was never seen
#define TLS_DROP_SSL_WRITE_UNCLAIMED 2 // SSL_write plaintext never matched to a socket write
#define TLS_DROP_REASONS             3

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, TLS_DROP_REASONS);
} tls_plaintext_dropped SEC(".maps");

static inline __attribute__((__always_inline__))
void count_tls_drop(__u32 reason) {
    __u64 *v = bpf_map_lookup_elem(&tls_plaintext_dropped, &reason);
    if (v) {
        *v += 1;
    }
}

// tls_plaintext_dropped_by_pid attributes the same losses to a process, so
// userspace can name the container and binary they come from. The per-CPU
// total above cannot. Userspace reads and deletes the entries periodically.
struct tls_drop_key {
    __u32 pid;
    __u32 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct tls_drop_key));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4096);
} tls_plaintext_dropped_by_pid SEC(".maps");

// count_tls_drop_by_pid also attributes a loss to the current process. It is
// used only from the TLS library uprobes, which are small, and kept out of
// the syscall programs, which are already near the verifier's limits.
static inline __attribute__((__always_inline__))
void count_tls_drop_by_pid(__u32 reason) {
    count_tls_drop(reason);
    struct tls_drop_key k = {};
    k.pid = bpf_get_current_pid_tgid() >> 32;
    k.reason = reason;
    __u64 *v = bpf_map_lookup_elem(&tls_plaintext_dropped_by_pid, &k);
    if (v) {
        __sync_fetch_and_add(v, 1);
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&tls_plaintext_dropped_by_pid, &k, &one, BPF_NOEXIST);
}

// mark_tls records that a TLS library hook handles this connection.
//
// A TLS connection is seen twice: once as plaintext by the Go crypto/tls or
// OpenSSL uprobes, and once as ciphertext by the read/write syscalls, both
// under the same pid+fd. The connection entry had no way to tell them apart,
// so once plaintext identified a connection as HTTP/2 its ciphertext took the
// same fast path into the same userspace parser. A TLS record header parses as
// an HTTP/2 frame header whose type is the high byte of the record length and
// whose length is 0x170303: 4KB records surfaced as "extension" frames, small
// ones were held as a partial 1.5MB frame that swallowed the real frames after
// them, and HPACK decoding desynchronised. Ciphertext is useless for L7, so
// once a hook has seen the connection the socket-level path ignores it.
//
// Whatever protocol was detected before the first mark came from handshake
// bytes, so it is cleared to be re-detected from plaintext.
static inline __attribute__((__always_inline__))
void mark_tls(struct connection *conn) {
    if (conn->tls) {
        return;
    }
    conn->tls = 1;
    conn->protocol = PROTOCOL_UNKNOWN;
}

#include "llm_capture.c"

static inline __attribute__((__always_inline__))
int http2_detection_allowed(struct connection *conn) {
    if (!conn) {
        return 0;
    }
    return (conn->bytes_sent + conn->bytes_received) < HTTP2_DETECTION_WINDOW_BYTES;
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
        } else if (get_socket_tuple_from_fd((__u32)fd, &tuple) && tuple.dport == 443) {
            // Port 443 fallback: TLS ClientHello detection requires reaching
            // the protocol-detection chain even when active_connections lookup
            // races with the connect (common for Go where connect and the
            // first write may run on different threads).
            conn_on_stack.dport = 443;
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

    if (!is_tls && conn != &conn_on_stack && conn->bytes_sent == 0 && llm_capture_enabled()) {
        llm_tag_by_destination(&cid, conn);
    }
    if (!is_tls) {
        __sync_fetch_and_add(&conn->bytes_sent, total_size);
    }

    if (is_tls) {
        mark_tls(conn);
        if (conn == &conn_on_stack) {
            // The mark must outlive this call for the socket-level ciphertext
            // that follows to be skipped, so the connection is tracked from
            // here on.
            conn_on_stack.timestamp = bpf_ktime_get_ns();
            bpf_map_update_elem(&active_connections, &cid, &conn_on_stack, BPF_NOEXIST);
            // Continue on the map entry (another CPU's, if it won the race):
            // the protocol detected below, and a loss recorded by
            // send_event, would otherwise be written to this stack copy and
            // discarded, and the next write would have to detect afresh.
            struct connection *tracked = bpf_map_lookup_elem(&active_connections, &cid);
            if (tracked) {
                conn = tracked;
                // If another CPU inserted it first (the TCP connect path
                // does, with tls 0), the mark above went to the stack copy.
                mark_tls(conn);
            }
        }
    } else if (conn->tls) {
        if (is_tls_clienthello(payload, size)) {
            // A ClientHello on a TLS-marked fd is a new session on a reused
            // fd whose entry was never replaced: start over so its SNI is
            // captured below and its plaintext is detected afresh.
            conn->tls = 0;
            conn->protocol = PROTOCOL_UNKNOWN;
        } else {
            count_ciphertext_skip(0);
            return 0;
        }
    }

    if (conn != &conn_on_stack && llm_capture(&cid, conn, 0, payload, size, total_size)) {
        return 0;
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
        COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        if (is_tls) { bpf_printk("l7_H2_SENT: pid=%u fd=%llu size=%llu", cid.pid, fd, size); }
        return 0;
    }

    if (req->protocol == PROTOCOL_UNKNOWN) { // Only detect protocol if it's not already known
        // TLS ClientHello detection — capture SNI to enable LLM provider
        // tagging on long-lived HTTP/2 connections where HPACK :authority
        // decoding fails after a mid-stream agent attach.
        if (conn->dport == 443 && is_tls_clienthello(payload, size)) {
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_TLS_CLIENTHELLO;
            e->method = 0;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = size;
            COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        }

        // Port-based HTTP/2 hint: Try HTTP/2 detection first for HTTPS traffic (port 443/8443)
        // Most modern HTTPS traffic uses HTTP/2, and this helps detect gRPC DATA frames
        // that don't have the connection preface.
        //
        // The client connection preface is unambiguous on any port, and must be
        // checked before the detectors below: is_redis_query takes anything
        // starting with an uppercase letter, "PRI * HTTP/2.0" included. On
        // other ports the connection was cached as Redis, and every write
        // until the first server frame was read (the preface and, from Go and
        // gRPC clients, the first request's headers) was lost. Those headers
        // carry most of the HPACK dynamic table's insertions, so the table
        // was missing them for the life of the connection.
        if (conn->dport != 53 && http2_detection_allowed(conn) &&
            (is_http2_client_preface(payload, size) ||
             (is_likely_http2_port(conn->dport) && looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)))) {
            conn->protocol = PROTOCOL_HTTP2; // Cache for subsequent frames
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_CLIENT_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = size;
            COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
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
        } else if (http2_detection_allowed(conn) && looks_like_http2_frame(payload, size, METHOD_HTTP2_CLIENT_FRAMES)) {
            // HTTP/2 detected on non-standard port
            conn->protocol = PROTOCOL_HTTP2; // Cache for subsequent frames
            struct l7_event *e = reserve_l7_event();
            if (!e) { return 0; }
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_CLIENT_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = size;
            COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
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
        COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
        send_event(ctx, e, cid, conn);
        return 0;
    }
    if (req->protocol == PROTOCOL_MYSQL && req->request_type == MYSQL_COM_STMT_CLOSE) {
        struct l7_event *e = reserve_l7_event();
        if (!e) { return 0; }
        e->protocol = PROTOCOL_MYSQL;
        e->method = METHOD_STATEMENT_CLOSE;
        e->payload_size = size;
        COPY_PAYLOAD_RINGBUF(conn, L7_LOST_WRITES, e->payload, size, payload);
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

    if (is_tls) {
        mark_tls(conn);
    } else if (conn->tls) {
        count_ciphertext_skip(1);
        return 0;
    }

    if (conn != &conn_on_stack && llm_capture(&cid, conn, 1, payload, total_size, total_size)) {
        return 0;
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
        COPY_PAYLOAD_RINGBUF(conn, L7_LOST_READS, e->payload, ret, payload);
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
            COPY_PAYLOAD_RINGBUF(conn, L7_LOST_READS, e->payload, ret, payload);
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
        } else if (http2_detection_allowed(conn) && looks_like_http2_frame(payload, ret, METHOD_HTTP2_SERVER_FRAMES)) {
            // HTTP/2 detected - cache protocol for subsequent frames
            conn->protocol = PROTOCOL_HTTP2;
            e->protocol = PROTOCOL_HTTP2;
            e->method = METHOD_HTTP2_SERVER_FRAMES;
            e->duration = bpf_ktime_get_ns();
            e->payload_size = ret;
            COPY_PAYLOAD_RINGBUF(conn, L7_LOST_READS, e->payload, ret, payload);
            send_event(ctx, e, cid, conn);
            return 0;
        } else {
            discard_l7_event(e);
            return 0;
        }
    }

    e->protocol = req->protocol;
    e->payload_size = req->payload_size;
    COPY_PAYLOAD_RINGBUF(conn, L7_LOST_READS, e->payload, req->payload_size, req->payload);
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
    COPY_PAYLOAD_RINGBUF(conn, L7_LOST_READS, e->response, ret, payload);
    send_event(ctx, e, cid, conn);
    return 0;
}

// ssl_socket_fd reports whether fd is a socket worth attributing TLS to: a
// tracked connection, or a socket the TCP tracking missed (connections that
// predate the agent). It keeps a log write that lands between SSL_write and
// the application's send() from claiming the plaintext.
static inline __attribute__((__always_inline__))
int ssl_socket_fd(__u32 pid, __u64 fd) {
    if (fd <= 2) {
        return 0;
    }
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;
    if (bpf_map_lookup_elem(&active_connections, &cid)) {
        return 1;
    }
    struct socket_tuple tuple = {};
    return get_socket_tuple_from_fd((__u32)fd, &tuple);
}

static inline __attribute__((__always_inline__))
void ssl_remember_fd(__u32 pid, __u64 ssl, __u64 fd) {
    struct ssl_key k = {};
    k.ssl = ssl;
    k.pid = pid;
    bpf_map_update_elem(&ssl_fds, &k, &fd, BPF_ANY);
}

// starts_with_tls_record reports whether a socket write begins with a TLS
// record header: content type 20-23 (change_cipher_spec, alert, handshake,
// application_data) and protocol version 3.x. buf is the write buffer, or an
// iovec array when iovlen is set.
static inline __attribute__((__always_inline__))
int starts_with_tls_record(char *buf, __u64 iovlen) {
    char *p = buf;
    if (iovlen) {
        struct iovec iov = {};
        if (bpf_probe_read(&iov, sizeof(iov), buf)) {
            return 0;
        }
        p = iov.buf;
    }
    __u8 h[3] = {};
    if (bpf_probe_read(&h, sizeof(h), p)) {
        return 0;
    }
    return h[0] >= 20 && h[0] <= 23 && h[1] == 3 && h[2] <= 4;
}

// ssl_claim_write hands the plaintext of a pending SSL_write to the socket
// write that carries it. Returns 1 when this write is that socket.
//
// *buf and *size describe the socket write on entry (an iovec array when
// iovlen is set) and the plaintext on a successful claim. Only a write that
// starts with a TLS record can carry the ciphertext: with a memory BIO the
// application sends the ciphertext itself after SSL_write returns, and an
// unrelated write on the same thread in between (a DNS query, a log line, a
// metrics datagram) used to take the plaintext and be marked as TLS.
static inline __attribute__((__always_inline__))
int ssl_claim_write(__u64 tid, __u64 fd, char **buf, __u64 *size, __u64 iovlen) {
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_write_pending, &tid);
    if (!args) {
        return 0;
    }
    if (bpf_ktime_get_ns() - args->ns > SSL_PENDING_WRITE_TTL_NS) {
        bpf_map_delete_elem(&ssl_write_pending, &tid);
        count_tls_drop(TLS_DROP_SSL_WRITE_UNCLAIMED);
        return 0;
    }
    __u32 pid = tid >> 32;
    if (!ssl_socket_fd(pid, fd)) {
        return 0;
    }
    if (!starts_with_tls_record(*buf, iovlen)) {
        return 0;
    }
    // This write's ciphertext is replaced by the plaintext below, so the
    // connection's sent bytes would otherwise never include it. The size of
    // a vectored write is not known here; it is left out.
    __u64 ciphertext_size = *size;
    *buf = args->buf;
    *size = args->size;
    ssl_remember_fd(pid, args->ssl, fd);
    bpf_map_delete_elem(&ssl_write_pending, &tid);
    if (ciphertext_size) {
        struct connection_id cid = {};
        cid.pid = pid;
        cid.fd = fd;
        struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
        if (conn) {
            __sync_fetch_and_add(&conn->bytes_sent, ciphertext_size);
        }
    }
    return 1;
}

// ssl_note_read_fd records the socket a pending SSL_read pulls ciphertext from.
static inline __attribute__((__always_inline__))
void ssl_note_read_fd(__u64 tid, __u64 fd) {
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_pending, &tid);
    if (!args || args->fd) {
        return;
    }
    __u32 pid = tid >> 32;
    if (!ssl_socket_fd(pid, fd)) {
        return;
    }
    args->fd = fd;
    ssl_remember_fd(pid, args->ssl, fd);
    // This read pulls ciphertext for SSL_read: mark the connection now so the
    // read itself is skipped, not just the ones after SSL_read returns.
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;
    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn) {
        mark_tls(conn);
    }
}

// The write handlers make a single trace_enter_write call with either the TLS
// plaintext or the raw buffer, rather than one call each: the function is
// inlined, and a second copy would double programs that are already ~6k
// instructions.
SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    char *buf = ctx->buf;
    __u64 size = ctx->size;
    __u16 is_tls = ssl_claim_write(bpf_get_current_pid_tgid(), ctx->fd, &buf, &size, 0);
    return trace_enter_write(ctx, ctx->fd, is_tls, buf, size, 0);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    char *buf = ctx->buf;
    __u64 size = 0;
    __u64 iovlen = ctx->size;
    __u16 is_tls = ssl_claim_write(bpf_get_current_pid_tgid(), ctx->fd, &buf, &size, iovlen);
    if (is_tls) {
        iovlen = 0;
    }
    return trace_enter_write(ctx, ctx->fd, is_tls, buf, size, iovlen);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_enter_sendmsg(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    struct user_msghdr msghdr = {};
    if (bpf_probe_read(&msghdr, sizeof(msghdr), (void *)ctx->buf)) {
        return 0;
    }
    char *buf = (char*)msghdr.msg_iov;
    __u64 size = 0;
    __u64 iovlen = msghdr.msg_iovlen;
    __u16 is_tls = ssl_claim_write(bpf_get_current_pid_tgid(), ctx->fd, &buf, &size, iovlen);
    if (is_tls) {
        iovlen = 0;
    }
    return trace_enter_write(ctx, ctx->fd, is_tls, buf, size, iovlen);
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
    char *buf = ctx->buf;
    __u64 size = ctx->size;
    __u16 is_tls = ssl_claim_write(bpf_get_current_pid_tgid(), ctx->fd, &buf, &size, 0);
    return trace_enter_write(ctx, ctx->fd, is_tls, buf, size, 0);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    ssl_note_read_fd(id, ctx->fd);
    return trace_enter_read(id, pid, ctx->fd, ctx->buf, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    ssl_note_read_fd(id, ctx->fd);
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
    ssl_note_read_fd(id, ctx->fd);
    return trace_enter_read(id, pid, ctx->fd, (char*)msghdr.msg_iov, 0, msghdr.msg_iovlen);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    ssl_note_read_fd(id, ctx->fd);
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
