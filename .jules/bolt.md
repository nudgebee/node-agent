## 2024-05-21 - Registry Event Loop Optimization
**Learning:** The `handleEvents` loop in `Registry` naively iterated all containers for every `TCPRetransmit` event, causing high CPU/allocations under network stress.
**Action:** Implemented PID-based fast path lookup and slice reuse to optimize the hot path.
