## 2025-01-21 - eBPF Event Parsing Performance
**Learning:** `binary.Read` uses reflection and is extremely slow for high-frequency eBPF event parsing. Manual parsing using `binary.LittleEndian` provides ~100x speedup and avoids unnecessary allocations.
**Action:** Prefer manual binary parsing for all hot-path event processing loops.

## 2025-01-21 - L7 Event Payload Copying
**Learning:** `binary.Read` reads the full struct size, including large fixed-size arrays (e.g. 4KB payload), even if the actual data is small.
**Action:** Manually parse headers and copy only the effective payload size to avoid wasted memory bandwidth.
