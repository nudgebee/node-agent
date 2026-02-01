## 2025-02-01 - Zero-Alloc Patterns
**Learning:** Parsing IP addresses from strings/bytes (like in `/proc/net/tcp`) using `make([]byte, ...)` creates significant pressure on the GC in hot paths. Using stack-allocated arrays `[16]byte` and decoding directly into them eliminates these allocations entirely.
**Action:** Always prefer `[N]byte` over `make([]byte, N)` for small, fixed-size buffers in parsing loops, especially for IP addresses and ports.
