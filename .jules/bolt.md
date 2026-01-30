## 2025-01-30 - Binary Deserialization Overhead
**Learning:** `binary.Read` incurs massive overhead (~40,000x slower) for reading C-structs from eBPF buffers compared to manual `binary.LittleEndian` parsing, due to reflection and unnecessary full-struct allocation/copying.
**Action:** Always use manual parsing with `binary.LittleEndian` for high-frequency eBPF event loops. Avoid decoding into large structs with fixed-size arrays; instead, read only the header and slice the payload.
