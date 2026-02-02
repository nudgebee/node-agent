## 2026-02-02 - Avoid binary.Read for eBPF events
**Learning:** `binary.Read` uses reflection and causes significant heap allocations (allocating the target struct) and CPU overhead, especially for large structs like `l7Event` (8KB).
**Action:** Use manual parsing with `binary.LittleEndian` and slice operations. For large payloads, copy only the needed bytes to small slices instead of allocating the full struct.
