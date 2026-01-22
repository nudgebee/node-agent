## 2025-05-19 - Manual Binary Parsing vs binary.Read
**Learning:** `binary.Read` uses reflection and can be significantly slower (orders of magnitude) than manual parsing using `binary.LittleEndian.UintXX`, especially in hot loops like eBPF event processing. Additionally, `binary.Read` forces full struct allocation and copying, which is wasteful for large structs where only a part of the data is needed (e.g. variable length payloads).
**Action:** For high-frequency binary data deserialization, prefer manual parsing with `encoding/binary` and explicit bounds checking.
