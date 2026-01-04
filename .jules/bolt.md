## 2024-05-23 - Flag Parsing Performance
**Learning:** `kingpin` flags are global variables but accessing and processing their values (e.g. `strings.Split` on a comma-separated list) inside a hot path (like HTTP request parsing) can cause significant overhead due to repeated allocations.
**Action:** Cache the processed value of configuration flags, especially for high-frequency operations. Use `sync.RWMutex` or `atomic.Value` to ensure thread-safe access if the flag value can change (even if only in tests).
