## 2024-01-19 - eBPF Event Parsing Optimization
**Learning:** `binary.Read` uses reflection and is extremely slow for high-frequency eBPF event deserialization (orders of magnitude slower than manual parsing).
**Insight:** Go struct padding can cause mismatches with C structs (e.g., `tcpEvent` 102 bytes in C vs 104 in Go), making `unsafe.Pointer` risky without careful verification.
**Action:** Use manual parsing with `binary.LittleEndian` for eBPF events. It is safe, robust against padding issues, and nearly as fast as `unsafe.Pointer` (and ~7000x faster than `binary.Read`).
