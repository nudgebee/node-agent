# Bolt's Journal

## 2025-02-23 - [eBPF Event Deserialization Strategy]
**Learning:** The `tcpEvent` struct has a size mismatch (102 bytes raw vs 104 bytes Go struct) preventing `unsafe.Pointer` casting. `binary.Read` must be used for this specific struct.
**Action:** When optimizing `ebpftracer` events, check struct alignment carefully. For `l7Event`, `procEvent`, and `fileEvent`, padding is added to match C layout, allowing zero-copy parsing.

## 2025-02-23 - [Large Event Deserialization]
**Learning:** `l7Event` is large (>8KB). `binary.Read` is extremely slow (~100k ns/op) compared to unsafe cast (~1.2 ns/op).
**Action:** Always prefer `unsafe.Pointer` cast for large structs where memory layout matches.
