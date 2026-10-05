// Go internal ABI specification: https://go.dev/s/regabi
#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GOROUTINE(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64)
#define GO_PARAM1(x) (((PT_REGS_ARM64 *)(x))->regs[0])
#define GO_PARAM2(x) (((PT_REGS_ARM64 *)(x))->regs[1])
#define GO_PARAM3(x) (((PT_REGS_ARM64 *)(x))->regs[2])
#define GOROUTINE(x) (((PT_REGS_ARM64 *)(x))->regs[28])
#endif

#define IS_TLS_READ_ID 0x8000000000000000

struct go_interface {
    __s64 type;
    void* ptr;
};

// Go TLS offsets for extracting FD from tls.Conn
// This allows the offsets to be dynamically configured per-process
// based on DWARF info or Go version
struct go_tls_offsets {
    __s32 tls_conn_conn_offset;  // Offset of 'conn' field in crypto/tls.Conn
    __s32 conn_fd_offset;         // Offset of 'fd' field in net.conn
    __s32 netfd_pfd_offset;       // Offset of 'pfd' field in net.netFD
    __s32 fd_sysfd_offset;        // Offset of 'Sysfd' field in internal/poll.FD
    __u64 net_tcpconn_itab;       // itab for *net.TCPConn -> net.Conn
    __s32 netfd_family_offset;    // Offset of 'family' field in net.netFD
    __s32 netfd_sotype_offset;    // Offset of 'sotype' field in net.netFD
};

// Default offsets for Go 1.17+ standard library
// These are known stable values:
// - fdMutex is { uint64 state, uint32 rsema, uint32 wsema } = 16 bytes
// - Sysfd follows fdMutex at offset 16
// - poll.FD is 56 bytes, so net.netFD's family and sotype ints follow it at
//   56 and 64
#define DEFAULT_FD_SYSFD_OFFSET 16
#define DEFAULT_NETFD_FAMILY_OFFSET 56
#define DEFAULT_NETFD_SOTYPE_OFFSET 64

// Linux values; Go stores them in net.netFD unchanged.
#define GO_AF_INET     2
#define GO_AF_INET6    10
#define GO_SOCK_STREAM 1

// BPF map to store Go TLS offsets per process (TGID)
// Populated by user-space when attaching uprobes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // TGID (PID in user-space terms)
    __uint(value_size, sizeof(struct go_tls_offsets));
    __uint(max_entries, 1024);
} go_tls_offsets_map SEC(".maps");

// go_conn_netfd reads the *net.netFD and its Sysfd from a value laid out like
// net.TCPConn: net.TCPConn → net.conn → netFD → poll.FD → Sysfd. Nothing here
// checks that conn_data is one; see go_netfd_is_tcp.
static inline __attribute__((__always_inline__))
int go_conn_netfd(void* conn_data, struct go_tls_offsets *offsets, void **netfd, __u32 *fd) {
    __s32 fd_sysfd_offset = DEFAULT_FD_SYSFD_OFFSET;
    __s32 conn_fd_offset = 0;
    __s32 netfd_pfd_offset = 0;

    if (offsets) {
        fd_sysfd_offset = offsets->fd_sysfd_offset;
        conn_fd_offset = offsets->conn_fd_offset;
        netfd_pfd_offset = offsets->netfd_pfd_offset;
    }

    // Read the fd pointer from the concrete net.Conn implementation
    // The data pointer points to the concrete type (e.g., *net.TCPConn)
    // net.TCPConn embeds net.conn at offset 0, which has fd *netFD at offset 0
    void* netfd_ptr;
    if (bpf_probe_read(&netfd_ptr, sizeof(netfd_ptr), conn_data + conn_fd_offset)) {
        bpf_printk("go_tls: failed to read netfd_ptr from data+%d", conn_fd_offset);
        return 1;
    }
    bpf_printk("go_tls: netfd_ptr=%p", netfd_ptr);

    // Validate netfd_ptr is not null
    if (!netfd_ptr) {
        bpf_printk("go_tls: netfd_ptr is null");
        return 1;
    }

    // Read Sysfd from netFD.pfd.Sysfd
    // netFD has embedded poll.FD (pfd) at offset 0
    // poll.FD has Sysfd at offset 16 (after fdMutex)
    void* sysfd_addr = netfd_ptr + netfd_pfd_offset + fd_sysfd_offset;

    if (bpf_probe_read(fd, sizeof(*fd), sysfd_addr)) {
        bpf_printk("go_tls: failed to read Sysfd from %p (pfd_offset=%d, sysfd_offset=%d)",
                   sysfd_addr, netfd_pfd_offset, fd_sysfd_offset);
        return 1;
    }

    // Validate the fd is reasonable (0-65535 for most systems, but can be higher)
    if (*fd > 1000000) {
        bpf_printk("go_tls: suspicious fd value %d, likely wrong offset", *fd);
        return 1;
    }

    *netfd = netfd_ptr;
    return 0;
}

// go_netfd_is_tcp reports whether netfd is a net.netFD of a TCP socket, by
// its family and sotype fields, and returns its family. It is the check that
// what go_conn_netfd read was a netFD at all. A wrapper type read as a
// net.TCPConn yields a pointer to whatever the wrapper holds first, usually
// the itab of its inner connection, and the "Sysfd" read from it is the
// itab's type hash. At the family and sotype offsets an itab holds method
// pointers, never 2 or 10 followed by 1. The check reads only the
// application's memory, so it works whether or not the kernel has BTF.
static inline __attribute__((__always_inline__))
int go_netfd_is_tcp(void *netfd, struct go_tls_offsets *offsets, __u16 *family) {
    __s32 family_offset = DEFAULT_NETFD_FAMILY_OFFSET;
    __s32 sotype_offset = DEFAULT_NETFD_SOTYPE_OFFSET;
    if (offsets) {
        family_offset = offsets->netfd_family_offset;
        sotype_offset = offsets->netfd_sotype_offset;
    }
    __s64 fam = 0, sotype = 0;
    if (bpf_probe_read(&fam, sizeof(fam), netfd + family_offset) ||
        bpf_probe_read(&sotype, sizeof(sotype), netfd + sotype_offset)) {
        return 0;
    }
    if ((fam != GO_AF_INET && fam != GO_AF_INET6) || sotype != GO_SOCK_STREAM) {
        return 0;
    }
    *family = (__u16)fam;
    return 1;
}

// GO_CONN_MAX_DEPTH bounds how many net.Conn wrappers are unwrapped.
#define GO_CONN_MAX_DEPTH 4

// go_plausible_iface reports whether i looks like a non-nil Go interface
// value: both words user-space pointers rather than small integers.
static inline __attribute__((__always_inline__))
int go_plausible_iface(struct go_interface *i) {
    return (__u64)i->type > 4096 && (__u64)i->ptr > 4096;
}

#define GO_FD_SOCKET_MISMATCH  0
#define GO_FD_SOCKET_OK        1
#define GO_FD_SOCKET_UNCHECKED 2

// go_fd_socket_check reports whether fd is a TCP socket of the current
// process with the given address family (GO_FD_SOCKET_OK), or not
// (GO_FD_SOCKET_MISMATCH). Without kernel BTF there are no struct offsets to
// find the socket by, and it reports GO_FD_SOCKET_UNCHECKED.
static inline __attribute__((__always_inline__))
int go_fd_socket_check(__u32 fd, __u16 family) {
    __u32 zero = 0;
    struct socket_info_offsets *so = bpf_map_lookup_elem(&socket_info_offsets_map, &zero);
    if (!so || !so->offsets_valid) {
        return GO_FD_SOCKET_UNCHECKED;
    }
    void *socket = get_socket_from_fd(fd, so);
    if (!socket) {
        return GO_FD_SOCKET_MISMATCH;
    }
    short type = 0;
    void *sk = NULL;
    __u16 sk_family = 0;
    if (bpf_probe_read_kernel(&type, sizeof(type), socket + so->socket_type_offset) ||
        bpf_probe_read_kernel(&sk, sizeof(sk), socket + so->socket_sk_offset) || !sk ||
        bpf_probe_read_kernel(&sk_family, sizeof(sk_family), sk + so->sk_family_offset)) {
        return GO_FD_SOCKET_MISMATCH;
    }
    if (type != GO_SOCK_STREAM || sk_family != family) {
        return GO_FD_SOCKET_MISMATCH;
    }
    return GO_FD_SOCKET_OK;
}

// go_tls_fd_resolved counts the Go TLS calls whose socket fd was found, by
// how it was found and at which wrapper depth: index method *
// GO_CONN_MAX_DEPTH + depth. It is the success-side counterpart of
// TLS_DROP_GO_FD_UNKNOWN, and shows how much capture rests on the heuristic.
// Userspace exports it as node_agent_go_tls_fd_resolved_total{method,depth};
// the method indexes must match goTLSFdResolvedMethods in tracer.go.
#define GO_FD_RESOLVED_ITAB    0 // the level's itab is the binary's *net.TCPConn one
#define GO_FD_RESOLVED_SOCKET  1 // a TCP netFD, and the kernel confirms a TCP socket of its family
#define GO_FD_RESOLVED_SHAPE   2 // a TCP netFD; no kernel BTF to confirm the socket with
#define GO_FD_RESOLVED_METHODS 3
#define GO_FD_RESOLVED_SLOTS   (GO_FD_RESOLVED_METHODS * GO_CONN_MAX_DEPTH)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, GO_FD_RESOLVED_SLOTS);
} go_tls_fd_resolved SEC(".maps");

static inline __attribute__((__always_inline__))
int go_crypto_tls_get_fd_from_conn(struct pt_regs *ctx, __u32 *fd) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    // Look up offsets for this process
    struct go_tls_offsets *offsets = bpf_map_lookup_elem(&go_tls_offsets_map, &tgid);

    if (offsets) {
        bpf_printk("go_tls: using dynamic offsets for tgid=%u", tgid);
    } else {
        bpf_printk("go_tls: no offsets found for tgid=%u, using defaults", tgid);
    }

    // Step 1: Read the tls.Conn pointer from the first parameter (receiver)
    // In Go's register-based ABI, the receiver is in AX (x86_64) or X0 (arm64)
    void* tls_conn_ptr = (void*)GO_PARAM1(ctx);
    bpf_printk("go_tls: tls_conn_ptr=%p", tls_conn_ptr);

    // Step 2: Read the conn field (net.Conn interface) from tls.Conn
    // The conn field is at offset 0 and is an interface (16 bytes: itab + data)
    struct go_interface conn_interface;
    __s32 tls_conn_offset = 0;
    if (offsets) {
        tls_conn_offset = offsets->tls_conn_conn_offset;
    }

    if (bpf_probe_read(&conn_interface, sizeof(conn_interface), tls_conn_ptr + tls_conn_offset)) {
        bpf_printk("go_tls: failed to read conn interface from tls_conn_ptr+%d", tls_conn_offset);
        return 1;
    }
    bpf_printk("go_tls: conn_interface.type=%llx data=%p", conn_interface.type, conn_interface.ptr);

    // Step 3: Find the socket behind the connection. Applications and
    // libraries wrap net.Conn in their own types, each embedding the
    // connection it wraps as an interface field: first (offset 0), or after a
    // small counter or flag (offset 8). Proxies stack them; traefik's TLS
    // connections are TLSConn -> peekConn -> trackedConnection ->
    // *net.TCPConn, and VictoriaMetrics' scrape connections are statConn
    // {closed int32; net.Conn}. gRPC's syscallConn is the same shape.
    // Descend until a level is a TCP connection.
    __u64 tcp_itab = offsets ? offsets->net_tcpconn_itab : 0;
    struct go_interface c = conn_interface;
    __u32 slot = GO_FD_RESOLVED_SLOTS;
    void *netfd = NULL;
#pragma unroll
    for (int depth = 0; depth < GO_CONN_MAX_DEPTH; depth++) {
        if (tcp_itab && (__u64)c.type == tcp_itab) {
            // Exact: the binary's own *net.TCPConn itab.
            if (go_conn_netfd(c.ptr, offsets, &netfd, fd) == 0) {
                slot = GO_FD_RESOLVED_ITAB * GO_CONN_MAX_DEPTH + depth;
            }
            break;
        }
        // Without the itab (a stripped binary) or with one that does not
        // match (a PIE binary, whose symbol table holds it unrelocated), try
        // the level as a TCP connection. Believe it only if what it points to
        // is a TCP netFD, and, where the kernel's struct offsets are known,
        // if the fd is a TCP socket of the same family.
        __u16 family = 0;
        if (go_conn_netfd(c.ptr, offsets, &netfd, fd) == 0 && go_netfd_is_tcp(netfd, offsets, &family)) {
            int s = go_fd_socket_check(*fd, family);
            if (s == GO_FD_SOCKET_OK) {
                slot = GO_FD_RESOLVED_SOCKET * GO_CONN_MAX_DEPTH + depth;
                break;
            }
            if (s == GO_FD_SOCKET_UNCHECKED) {
                slot = GO_FD_RESOLVED_SHAPE * GO_CONN_MAX_DEPTH + depth;
                break;
            }
        }
        struct go_interface inner = {};
        if (bpf_probe_read(&inner, sizeof(inner), c.ptr) || !go_plausible_iface(&inner)) {
            if (bpf_probe_read(&inner, sizeof(inner), c.ptr + 8) || !go_plausible_iface(&inner)) {
                break;
            }
        }
        c = inner;
    }

    if (slot >= GO_FD_RESOLVED_SLOTS) {
        bpf_printk("go_tls: failed to extract fd");
        return 1;
    }
    __u64 *resolved = bpf_map_lookup_elem(&go_tls_fd_resolved, &slot);
    if (resolved) {
        *resolved += 1;
    }
    return 0;
}

// ensure_connection_tracked adds the connection to active_connections if not already tracked.
// This is necessary for Go applications because Go's goroutine scheduler moves goroutines
// between OS threads, causing the TCP connection tracking (which uses pid|tid as key) to fail.
// Returns 1 if connection exists or was added, 0 on failure.
static inline __attribute__((__always_inline__))
int ensure_connection_tracked(__u32 pid, __u64 fd) {
    struct connection_id cid = {};
    cid.pid = pid;
    cid.fd = fd;

    struct connection *conn = bpf_map_lookup_elem(&active_connections, &cid);
    if (conn) {
        bpf_printk("go_tls: connection already tracked pid=%u fd=%llu", pid, fd);
        // Mark before the socket read inside this TLS call, so its ciphertext
        // is skipped rather than parsed.
        mark_tls(conn);
        return 1;  // Connection already tracked
    }

    // Connection not tracked - add it now for Go TLS traffic
    struct connection new_conn = {};
    new_conn.timestamp = bpf_ktime_get_ns();
    new_conn.protocol = PROTOCOL_UNKNOWN;
    new_conn.tls = 1;
    // Not the real port: 443 marks the connection as HTTPS-like so the
    // port-gated HTTP/2 frame detection in trace_enter_write runs on it. Only
    // connections the TCP tracking missed get here (most often ones that
    // predate the agent), and their HTTP/2 traffic, gRPC on any port included,
    // carries no connection preface to detect it by. Events take their real
    // address and port from the socket (see send_event), so no label shows
    // this value.
    new_conn.dport = 443;

    int ret = bpf_map_update_elem(&active_connections, &cid, &new_conn, BPF_NOEXIST);
    if (ret == 0) {
        bpf_printk("go_tls: added connection to active_connections pid=%u fd=%llu", pid, fd);
    } else {
        bpf_printk("go_tls: FAILED to add connection pid=%u fd=%llu ret=%d", pid, fd, ret);
    }
    return 1;
}

SEC("uprobe/go_crypto_tls_write_enter")
int go_crypto_tls_write_enter(struct pt_regs *ctx) {
    // Debug: Log EVERY call to crypto/tls.(*Conn).Write
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    void* tls_conn_ptr_debug = (void*)GO_PARAM1(ctx);
    __u64 buf_size_debug = GO_PARAM3(ctx);
    bpf_printk("go_tls_write_enter: tgid=%u tls_conn=%p buf_size=%llu", pid, tls_conn_ptr_debug, buf_size_debug);

    __u32 fd;
    if (go_crypto_tls_get_fd_from_conn(ctx, &fd)) {
        count_tls_drop_by_pid(TLS_DROP_GO_FD_UNKNOWN);
        return 0;
    }

    // Ensure connection is tracked (fixes Go goroutine threading issue)
    ensure_connection_tracked(pid, fd);

    char *buf_ptr = (char*)GO_PARAM2(ctx);
    __u64 buf_size = GO_PARAM3(ctx);
    return trace_enter_write(ctx, fd, 1, buf_ptr, buf_size, 0);
}

// go_tls_write_args holds a crypto/tls.(*Conn).Write call between the probe
// at its entry and the probes at its returns, keyed like reads by process and
// goroutine.
//
// A Go function's entry runs again when its goroutine's stack has to grow
// there: the runtime copies the stack and restarts the function from its
// first instruction. A probe that emits at entry then sends the same write
// twice, and a duplicated write splices a copy of its bytes into the
// connection's stream: the HTTP/2 parser loses frame alignment for the rest
// of the connection, and a repeated header block inserts its HPACK entries
// twice. Stacks grow again after the GC shrinks them, so this recurs for the
// life of a process. Saving the arguments at entry, which a restart only
// overwrites, and emitting once at return sends every write exactly once.
struct go_tls_write_args {
    __u64 fd;
    char *buf;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct go_tls_write_args));
    __uint(max_entries, 10240);
} go_tls_write_args SEC(".maps");

SEC("uprobe/go_crypto_tls_write_save")
int go_crypto_tls_write_save(struct pt_regs *ctx) {
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd;
    if (go_crypto_tls_get_fd_from_conn(ctx, &fd)) {
        count_tls_drop_by_pid(TLS_DROP_GO_FD_UNKNOWN);
        return 0;
    }
    ensure_connection_tracked(pid, fd);
    struct go_tls_write_args args = {
        .fd = fd,
        .buf = (char*)GO_PARAM2(ctx),
        .size = GO_PARAM3(ctx),
    };
    __u64 id = pid << 32 | GOROUTINE(ctx);
    bpf_map_update_elem(&go_tls_write_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("uprobe/go_crypto_tls_write_exit")
int go_crypto_tls_write_exit(struct pt_regs *ctx) {
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 id = pid << 32 | GOROUTINE(ctx);
    struct go_tls_write_args *a = bpf_map_lookup_elem(&go_tls_write_args, &id);
    if (!a) {
        return 0;
    }
    struct go_tls_write_args args = *a;
    bpf_map_delete_elem(&go_tls_write_args, &id);
    // Write returns the bytes written; on an error part of the buffer may
    // not have been sent.
    long n = GO_PARAM1(ctx);
    if (n <= 0) {
        return 0;
    }
    __u64 size = args.size;
    if ((__u64)n < size) {
        size = n;
    }
    return trace_enter_write(ctx, args.fd, 1, args.buf, size, 0);
}

SEC("uprobe/go_crypto_tls_read_enter")
int go_crypto_tls_read_enter(struct pt_regs *ctx) {
    // Debug: Log EVERY call to crypto/tls.(*Conn).Read
    __u64 pid_tgid_debug = bpf_get_current_pid_tgid();
    __u32 tgid_debug = pid_tgid_debug >> 32;
    void* tls_conn_ptr_debug = (void*)GO_PARAM1(ctx);
    bpf_printk("go_tls_read_enter: tgid=%u tls_conn=%p", tgid_debug, tls_conn_ptr_debug);

    __u32 fd;
    if (go_crypto_tls_get_fd_from_conn(ctx, &fd)) {
        count_tls_drop_by_pid(TLS_DROP_GO_FD_UNKNOWN);
        return 0;
    }
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 pid = pid_tgid >> 32;

    // Ensure connection is tracked (fixes Go goroutine threading issue)
    ensure_connection_tracked(pid, fd);

    __u64 id = pid << 32 | goroutine_id | IS_TLS_READ_ID;
    return trace_enter_read(id, pid, fd, buf_ptr, 0, 0);
}

SEC("uprobe/go_crypto_tls_read_exit")
int go_crypto_tls_read_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 goroutine_id = GOROUTINE(ctx);
    __u64 id = pid << 32 | goroutine_id | IS_TLS_READ_ID;
    long int ret = GO_PARAM1(ctx);
    return trace_exit_read(ctx, id, pid, 1, ret);
}
