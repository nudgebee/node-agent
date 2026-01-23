## 2025-01-23 - Stack Allocation for Temporary Buffers
**Learning:** Using `make([]byte, n)` for small, temporary buffers (like IP parsing) in hot loops causes significant allocation overhead. Replacing them with stack-allocated arrays (e.g., `var buf [16]byte; slice := buf[:]`) eliminates these allocations entirely.
**Action:** Look for small `make` calls in hot paths (especially in `proc` parsing) and replace them with stack buffers where the size is bounded and small.
