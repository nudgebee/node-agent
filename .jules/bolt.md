## 2025-02-04 - Hex Decoding Optimizations
**Learning:** `encoding/hex.Decode` can decode directly into stack-allocated arrays (`[N]byte`), avoiding heap allocations from `make([]byte)`. This is critical for hot paths like parsing `/proc/net` files.
**Action:** Use `[N]byte` buffers and pass slice `buf[:]` to `hex.Decode` instead of allocating new slices.
