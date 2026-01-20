## 2025-01-20 - Performance: Manual Parsing vs binary.Read
**Learning:** `binary.Read` is extremely slow (~200x slower) compared to manual parsing using `binary.LittleEndian` for struct deserialization, likely due to reflection overhead.
**Action:** When deserializing high-frequency events (like eBPF events), always use manual parsing with `binary.ByteOrder` methods and explicit bounds checks instead of `binary.Read`.

## 2025-01-20 - Go Struct Padding & eBPF
**Learning:** eBPF structs often map to Go structs with padding. `binary.Read` handles fields individually but ignores inter-field padding in the source buffer unless the Go struct fields align exactly with the source layout including padding.
**Action:** When manually parsing, be aware of alignment and padding bytes. Calculate offsets manually matching the C struct layout.
