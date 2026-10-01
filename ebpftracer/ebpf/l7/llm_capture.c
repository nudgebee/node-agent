// LLM capture channel.
//
// The generic L7 path keeps one bounded request event and the first read of
// the response. That is enough for status codes and latency, but an LLM API
// reports token usage at the end of the response body, or in the last event
// of a stream, so usage was out of reach. Connections that userspace has
// marked in llm_conns instead have every read and write copied, in order, and
// userspace reassembles the HTTP exchanges.
//
// The chunks go into l7_events, the same ring buffer as generic events, marked
// by PROTOCOL_LLM_CAPTURE at the offset where an l7_event keeps its protocol.
// Userspace marks a connection only after it has seen the TLS ClientHello, so
// the first frames of the connection may already have taken the generic path;
// a single ordered buffer lets userspace splice those and the capture chunks
// into one stream without a gap or a reordering.

// Each read or write is copied in up to two chunks of LLM_CHUNK-1 bytes; the
// mask that bounds a copy for the verifier cannot express LLM_CHUNK itself.
// Two chunks cover a full 64KB read. Anything beyond is reported in
// skip_after so userspace can keep the stream aligned.
#define LLM_CHUNK 65536
#define PROTOCOL_LLM_CAPTURE 0xFE

// The first 33 bytes mirror struct l7_event: fd, connection_timestamp and pid
// in the same places, and protocol at offset 32.
struct llm_event {
    __u64 fd;
    __u64 connection_timestamp;
    __u32 pid;
    __u32 len;        // bytes of data that follow
    __u64 ts;
    __u8 protocol;    // always PROTOCOL_LLM_CAPTURE
    __u8 direction;   // 0 = written by the application, 1 = read by it
    __u8 padding[6];
    __u64 skip_after; // bytes of the original buffer not captured after this chunk
    char data[LLM_CHUNK];
};

// Scratch space for one llm_event per CPU. A per-CPU array cannot hold a
// value this large (they are capped at 32KB), so this is a plain array indexed
// by CPU, sized by userspace to the number of possible CPUs before loading.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct llm_event);
    __uint(max_entries, 1);
} llm_event_heap SEC(".maps");

// llm_capture_drops counts chunks lost because l7_events was full.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} llm_capture_drops SEC(".maps");

static inline __attribute__((__always_inline__))
void llm_emit(struct llm_event *e, char *src, __u64 len, __u64 skip_after) {
    asm volatile ("%0 &= %1" : "+r"(len) : "i"(LLM_CHUNK - 1));
    if (bpf_probe_read(e->data, len, src)) {
        return;
    }
    e->len = len;
    e->skip_after = skip_after;
    if (bpf_ringbuf_output(&l7_events, e, __builtin_offsetof(struct llm_event, data) + len, 0)) {
        __u32 zero = 0;
        __u64 *drops = bpf_map_lookup_elem(&llm_capture_drops, &zero);
        if (drops) {
            *drops += 1;
        }
    }
}

// llm_capture copies buf if the connection is marked for LLM capture, and
// returns 1 if it did, so the caller skips the generic path. size bytes are
// readable at buf; total is the size of the whole read or write, which is
// larger only when buf holds an iovec prefix.
static inline __attribute__((__always_inline__))
int llm_capture(struct connection_id *cid, struct connection *conn, __u8 direction, char *buf, __u64 size, __u64 total) {
    __u64 *conn_ts = bpf_map_lookup_elem(&llm_conns, cid);
    if (!conn_ts) {
        return 0;
    }
    if (*conn_ts == 0) {
        // Marked from a ClientHello sent before the connection had an entry
        // of its own (a Go connect the TCP tracking missed): the first capture
        // on this fd binds the mark to the connection it belongs to.
        *conn_ts = conn->timestamp;
    } else if (*conn_ts != conn->timestamp) {
        bpf_map_delete_elem(&llm_conns, cid);
        return 0;
    }
    __u32 cpu = bpf_get_smp_processor_id();
    struct llm_event *e = bpf_map_lookup_elem(&llm_event_heap, &cpu);
    if (!e) {
        return 1;
    }
    e->ts = bpf_ktime_get_ns();
    e->protocol = PROTOCOL_LLM_CAPTURE;
    e->connection_timestamp = conn->timestamp;
    e->fd = cid->fd;
    e->pid = cid->pid;
    e->direction = direction;

    __u64 first = size < LLM_CHUNK - 1 ? size : LLM_CHUNK - 1;
    __u64 second = size - first;
    if (second > LLM_CHUNK - 1) {
        second = LLM_CHUNK - 1;
    }
    __u64 lost = total > first + second ? total - first - second : 0;
    if (second == 0) {
        llm_emit(e, buf, first, lost);
        return 1;
    }
    llm_emit(e, buf, first, 0);
    llm_emit(e, buf + first, second, lost);
    return 1;
}
