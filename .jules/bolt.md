## 2025-02-05 - Binary Read Overhead in eBPF Parsing
**Learning:** `binary.Read` is a massive performance bottleneck for high-frequency eBPF event parsing in Go, especially when reading into large structs (like `l7Event` > 8KB). It uses reflection and allocates memory.
**Action:** Replace `binary.Read` with manual parsing using `binary.LittleEndian` and slice indexing for hot paths. Benchmarks showed ~1500x speedup for `l7Event` parsing (70ns vs 105µs) and ~134x speedup for `tcpEvent` (8ns vs 1181ns). Ensure explicit bounds checks are added to prevent panics.
