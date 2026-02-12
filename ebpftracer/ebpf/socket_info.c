// socket_info.c - Socket info extraction from fd
// Based on DeepFlow's approach: use BTF to discover kernel struct offsets
// at runtime, then traverse task->files->fdt->fd[n]->private_data->sk

#ifndef __SOCKET_INFO_C__
#define __SOCKET_INFO_C__

// Struct to hold kernel struct offsets discovered via BTF in user-space
// These offsets vary by kernel version, so we discover them at runtime
struct socket_info_offsets {
    // task_struct offsets
    __s32 task_files_offset;           // task_struct->files

    // files_struct offsets
    __s32 files_fdt_offset;            // files_struct->fdt

    // fdtable offsets
    __s32 fdt_fd_offset;               // fdtable->fd (pointer to fd array)
    __s32 fdt_max_fds_offset;          // fdtable->max_fds

    // file offsets
    __s32 file_private_data_offset;    // file->private_data

    // socket offsets
    __s32 socket_sk_offset;            // socket->sk

    // sock_common offsets (connection tuple)
    __s32 sk_family_offset;            // sock_common->skc_family
    __s32 sk_daddr_offset;             // sock_common->skc_daddr (IPv4 dest)
    __s32 sk_rcv_saddr_offset;         // sock_common->skc_rcv_saddr (IPv4 src)
    __s32 sk_dport_offset;             // sock_common->skc_dport
    __s32 sk_num_offset;               // sock_common->skc_num (src port)
    __s32 sk_v6_daddr_offset;          // sock_common->skc_v6_daddr (IPv6 dest)
    __s32 sk_v6_rcv_saddr_offset;      // sock_common->skc_v6_rcv_saddr (IPv6 src)

    // Flags
    __u8 offsets_valid;                // Set to 1 when offsets are populated
    __u8 padding[3];
};

// Map to store offsets - populated by user-space after BTF discovery
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct socket_info_offsets));
    __uint(max_entries, 1);
} socket_info_offsets_map SEC(".maps");

// Socket tuple extracted from kernel sock struct
struct socket_tuple {
    __u8 saddr[16];      // Source address (IPv4 in first 4 bytes, or full IPv6)
    __u8 daddr[16];      // Destination address
    __u16 sport;         // Source port
    __u16 dport;         // Destination port
    __u16 family;        // AF_INET (2) or AF_INET6 (10)
    __u8 valid;          // 1 if extraction succeeded
    __u8 padding;
};

// Extract socket tuple from fd number
// Returns 1 on success, 0 on failure
static inline __attribute__((__always_inline__))
int get_socket_tuple_from_fd(__u32 fd, struct socket_tuple *tuple) {
    // Initialize tuple
    __builtin_memset(tuple, 0, sizeof(*tuple));

    // Get offsets from map
    __u32 zero = 0;
    struct socket_info_offsets *offsets = bpf_map_lookup_elem(&socket_info_offsets_map, &zero);
    if (!offsets || !offsets->offsets_valid) {
        return 0;
    }

    // Get current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    // Read files_struct pointer: task->files
    void *files = NULL;
    if (bpf_probe_read_kernel(&files, sizeof(files), (void *)task + offsets->task_files_offset)) {
        return 0;
    }
    if (!files) {
        return 0;
    }

    // Read fdtable pointer: files->fdt
    void *fdt = NULL;
    if (bpf_probe_read_kernel(&fdt, sizeof(fdt), (void *)files + offsets->files_fdt_offset)) {
        return 0;
    }
    if (!fdt) {
        return 0;
    }

    // Read max_fds to validate fd
    __u32 max_fds = 0;
    if (bpf_probe_read_kernel(&max_fds, sizeof(max_fds), (void *)fdt + offsets->fdt_max_fds_offset)) {
        return 0;
    }
    if (fd >= max_fds) {
        return 0;
    }

    // Read fd array pointer: fdt->fd
    void **fd_array = NULL;
    if (bpf_probe_read_kernel(&fd_array, sizeof(fd_array), (void *)fdt + offsets->fdt_fd_offset)) {
        return 0;
    }
    if (!fd_array) {
        return 0;
    }

    // Read file pointer: fd_array[fd]
    void *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd])) {
        return 0;
    }
    if (!file) {
        return 0;
    }

    // Read socket pointer: file->private_data
    // For socket fds, private_data points to struct socket
    void *socket = NULL;
    if (bpf_probe_read_kernel(&socket, sizeof(socket), (void *)file + offsets->file_private_data_offset)) {
        return 0;
    }
    if (!socket) {
        return 0;
    }

    // Read sock pointer: socket->sk
    void *sk = NULL;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), (void *)socket + offsets->socket_sk_offset)) {
        return 0;
    }
    if (!sk) {
        return 0;
    }

    // Read address family
    __u16 family = 0;
    if (bpf_probe_read_kernel(&family, sizeof(family), (void *)sk + offsets->sk_family_offset)) {
        return 0;
    }
    tuple->family = family;

    // Read ports (same for IPv4 and IPv6)
    __be16 dport_be = 0;
    __u16 sport = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(dport_be), (void *)sk + offsets->sk_dport_offset);
    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)sk + offsets->sk_num_offset);
    tuple->dport = bpf_ntohs(dport_be);
    tuple->sport = sport;

    // Read addresses based on family
    if (family == 2) {  // AF_INET
        bpf_probe_read_kernel(tuple->saddr, 4, (void *)sk + offsets->sk_rcv_saddr_offset);
        bpf_probe_read_kernel(tuple->daddr, 4, (void *)sk + offsets->sk_daddr_offset);
        tuple->valid = 1;
    } else if (family == 10) {  // AF_INET6
        bpf_probe_read_kernel(tuple->saddr, 16, (void *)sk + offsets->sk_v6_rcv_saddr_offset);
        bpf_probe_read_kernel(tuple->daddr, 16, (void *)sk + offsets->sk_v6_daddr_offset);
        tuple->valid = 1;
    }

    return tuple->valid;
}

#endif // __SOCKET_INFO_C__
