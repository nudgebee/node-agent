## 2025-01-31 - Zero-alloc IP parsing
**Learning:** `netaddr.FromStdIP(net.IP(...))` causes heap allocations because `net.IP` is a slice. Using `netaddr.IPv4` or `netaddr.IPFrom16` with stack-allocated arrays avoids these allocations completely.
**Action:** Always prefer `netaddr.IPv4/IPFrom16` with `[4]byte` or `[16]byte` buffers over `net.IP` slice wrappers when performance matters.
