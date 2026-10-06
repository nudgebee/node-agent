// OpenSSL uprobes. Nothing here reads the SSL or BIO structs: the fd an SSL
// object talks to is learned from the socket syscalls on the same thread (see
// ssl_write_pending/ssl_read_pending/ssl_fds in l7.c), so the same programs
// serve every OpenSSL release and applications that bring their own BIO.

static inline __attribute__((__always_inline__))
__u64 ssl_known_fd(__u32 pid, __u64 ssl) {
    struct ssl_key k = {};
    k.ssl = ssl;
    k.pid = pid;
    __u64 *fd = bpf_map_lookup_elem(&ssl_fds, &k);
    if (!fd) {
        return 0;
    }
    return *fd;
}

// SSL_write(ssl, buf, num) and SSL_write_ex(ssl, buf, num, written).
SEC("uprobe/openssl_SSL_write_enter")
int openssl_SSL_write_enter(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    char *buf = (char *)PT_REGS_PARM2(ctx);
    __u64 size = PT_REGS_PARM3(ctx);

    __u64 fd = ssl_known_fd(pid, ssl);
    if (fd) {
        ensure_connection_tracked(pid, fd);
        return trace_enter_write(ctx, fd, 1, buf, size, 0);
    }
    // First write on this SSL object: the socket write that follows on this
    // thread names the fd (sys_enter_write and friends in l7.c). A pending
    // write still here was never claimed, and its plaintext is lost.
    if (bpf_map_lookup_elem(&ssl_write_pending, &tid)) {
        count_tls_drop_by_pid(TLS_DROP_SSL_WRITE_UNCLAIMED);
    }
    struct ssl_args args = {};
    args.buf = buf;
    args.size = size;
    args.ssl = ssl;
    args.ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&ssl_write_pending, &tid, &args, BPF_ANY);
    return 0;
}

static inline __attribute__((__always_inline__))
int ssl_read_enter(struct pt_regs *ctx, __u64 *ret) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct ssl_args args = {};
    args.buf = (char *)PT_REGS_PARM2(ctx);
    args.ret = ret;
    args.ssl = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_read_pending, &tid, &args, BPF_ANY);
    return 0;
}

// SSL_read(ssl, buf, num)
SEC("uprobe/openssl_SSL_read_enter")
int openssl_SSL_read_enter(struct pt_regs *ctx) {
    return ssl_read_enter(ctx, 0);
}

// SSL_read_ex(ssl, buf, num, readbytes)
SEC("uprobe/openssl_SSL_read_ex_enter")
int openssl_SSL_read_ex_enter(struct pt_regs *ctx) {
    return ssl_read_enter(ctx, (__u64 *)PT_REGS_PARM4(ctx));
}

SEC("uprobe/openssl_SSL_read_exit")
int openssl_SSL_read_exit(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    struct ssl_args *args = bpf_map_lookup_elem(&ssl_read_pending, &tid);
    if (!args) {
        return 0;
    }
    char *buf = args->buf;
    __u64 *ret_ptr = args->ret;
    __u64 fd = args->fd;
    __u64 ssl = args->ssl;
    bpf_map_delete_elem(&ssl_read_pending, &tid);

    if (!fd) {
        // No socket read inside SSL_read: either the plaintext was already
        // buffered, or a memory BIO application (.NET) read the ciphertext
        // itself beforehand.
        fd = ssl_known_fd(pid, ssl);
        if (!fd) {
            if ((int)PT_REGS_RC(ctx) > 0) {
                count_tls_drop_by_pid(TLS_DROP_SSL_READ_FD_UNKNOWN);
            }
            return 0;
        }
    }
    ensure_connection_tracked(pid, fd);
    __u64 id = tid | IS_TLS_READ_ID;
    trace_enter_read(id, pid, fd, buf, ret_ptr, 0);
    return trace_exit_read(ctx, id, pid, 1, (int)PT_REGS_RC(ctx));
}

// SSL_free(ssl): the pointer may be reused by the next SSL_new, which must not
// inherit this connection's fd.
SEC("uprobe/openssl_SSL_free_enter")
int openssl_SSL_free_enter(struct pt_regs *ctx) {
    struct ssl_key k = {};
    k.ssl = (__u64)PT_REGS_PARM1(ctx);
    k.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&ssl_fds, &k);
    return 0;
}
