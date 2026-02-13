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
//
// Extended to support gRPC connections which wrap net.Conn in
// credentials.syscallConn interface (following DeepFlow's approach)
struct go_tls_offsets {
    __s32 tls_conn_conn_offset;  // Offset of 'conn' field in crypto/tls.Conn
    __s32 conn_fd_offset;         // Offset of 'fd' field in net.conn
    __s32 netfd_pfd_offset;       // Offset of 'pfd' field in net.netFD
    __s32 fd_sysfd_offset;        // Offset of 'Sysfd' field in internal/poll.FD
    // itab addresses for interface type detection (gRPC support)
    __u64 net_tcpconn_itab;       // itab for *net.TCPConn -> net.Conn
    __u64 grpc_syscallconn_itab;  // itab for *credentials.syscallConn -> net.Conn
    __s32 syscallconn_conn_offset; // Offset of 'Conn' field in credentials.syscallConn
};

// Default offsets for Go 1.17+ standard library
// These are known stable values:
// - fdMutex is { uint64 state, uint32 rsema, uint32 wsema } = 16 bytes
// - Sysfd follows fdMutex at offset 16
#define DEFAULT_FD_SYSFD_OFFSET 16
// Default offset for syscallConn.Conn field (typically 0 or 8)
#define DEFAULT_SYSCALLCONN_CONN_OFFSET 0

// BPF map to store Go TLS offsets per process (TGID)
// Populated by user-space when attaching uprobes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // TGID (PID in user-space terms)
    __uint(value_size, sizeof(struct go_tls_offsets));
    __uint(max_entries, 1024);
} go_tls_offsets_map SEC(".maps");

// Helper to extract FD from a net.TCPConn-like structure
// This handles the common case: net.TCPConn → net.conn → netFD → poll.FD → Sysfd
static inline __attribute__((__always_inline__))
int extract_fd_from_tcpconn(void* conn_data, struct go_tls_offsets *offsets, __u32 *fd) {
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
    if (*fd < 0 || *fd > 1000000) {
        bpf_printk("go_tls: suspicious fd value %d, likely wrong offset", *fd);
        return 1;
    }

    return 0;
}

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

    // Step 3: Check if this is a gRPC syscallConn wrapper and unwrap if needed
    // gRPC wraps connections in credentials.syscallConn which implements net.Conn
    // Structure: syscallConn { Conn net.Conn; rawConn syscall.RawConn }
    void* actual_conn_data = conn_interface.ptr;

    if (offsets && offsets->grpc_syscallconn_itab != 0) {
        // Check if this connection is wrapped in gRPC's syscallConn
        if ((__u64)conn_interface.type == offsets->grpc_syscallconn_itab) {
            bpf_printk("go_tls: detected gRPC syscallConn wrapper, unwrapping");

            // Read the underlying Conn interface from syscallConn
            // syscallConn.Conn is at offset syscallconn_conn_offset (typically 0)
            struct go_interface inner_conn;
            __s32 sc_offset = offsets->syscallconn_conn_offset;
            if (sc_offset == 0) {
                sc_offset = DEFAULT_SYSCALLCONN_CONN_OFFSET;
            }

            if (bpf_probe_read(&inner_conn, sizeof(inner_conn), conn_interface.ptr + sc_offset)) {
                bpf_printk("go_tls: failed to read inner conn from syscallConn+%d", sc_offset);
                return 1;
            }
            bpf_printk("go_tls: unwrapped inner_conn.type=%llx data=%p", inner_conn.type, inner_conn.ptr);

            // Use the unwrapped connection data
            actual_conn_data = inner_conn.ptr;
        }
    } else {
        // No itab info available - try heuristic detection
        // If FD extraction fails with direct approach, try treating as syscallConn
        // This is a fallback for when we don't have symbol information
        bpf_printk("go_tls: no itab info, trying direct extraction first");
    }

    // Step 4: Extract FD from the actual connection data
    if (extract_fd_from_tcpconn(actual_conn_data, offsets, fd) == 0) {
        bpf_printk("go_tls: extracted fd=%d", *fd);
        return 0;
    }

    // Step 5: If direct extraction failed and we haven't tried unwrapping,
    // try treating conn_interface.ptr as a wrapper struct
    if (actual_conn_data == conn_interface.ptr) {
        bpf_printk("go_tls: direct extraction failed, trying wrapper unwrap");

        // Try reading as if it's a wrapper with Conn interface at offset 0
        struct go_interface wrapper_inner;
        if (bpf_probe_read(&wrapper_inner, sizeof(wrapper_inner), conn_interface.ptr) == 0) {
            if (wrapper_inner.ptr != NULL && wrapper_inner.type != 0) {
                bpf_printk("go_tls: found wrapper inner.type=%llx data=%p",
                          wrapper_inner.type, wrapper_inner.ptr);

                if (extract_fd_from_tcpconn(wrapper_inner.ptr, offsets, fd) == 0) {
                    bpf_printk("go_tls: extracted fd=%d via wrapper unwrap", *fd);
                    return 0;
                }
            }
        }
    }

    bpf_printk("go_tls: failed to extract fd");
    return 1;
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
        return 1;  // Connection already tracked
    }

    // Connection not tracked - add it now for Go TLS traffic
    struct connection new_conn = {};
    new_conn.timestamp = bpf_ktime_get_ns();
    new_conn.protocol = PROTOCOL_UNKNOWN;
    // TODO: Extract actual destination port from socket instead of hardcoding
    // This requires reading socket info via bpf_get_socket_cookie or similar
    new_conn.dport = 443;  // Assume HTTPS for Go TLS

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
        return 0;
    }

    // Ensure connection is tracked (fixes Go goroutine threading issue)
    ensure_connection_tracked(pid, fd);

    char *buf_ptr = (char*)GO_PARAM2(ctx);
    __u64 buf_size = GO_PARAM3(ctx);
    return trace_enter_write(ctx, fd, 1, buf_ptr, buf_size, 0);
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
