# Performance Characteristics

> **Warning:** All values in this document are **estimated**. Actual measurements
> have not yet been taken. These numbers are based on chrony 4.5 reference
> measurements and architectural analysis, not empirical testing of chrony-rs.
> Do not rely on them for capacity planning or performance-sensitive decisions.

Expected performance data for `chrony-rs` under various conditions. Values marked
"estimated" are based on chrony 4.5 reference measurements and architectural
analysis; values marked "measured" are from the real compiled system.

## E9. NTP Packet Throughput

| Scenario | Rate (packets/s) | CPU | Notes |
|----------|-----------------|-----|-------|
| Client request (48B send, 48B recv) | ~50,000/s estimated | x86-64 @ 2.5GHz | Single poll loop, no authentication |
| Client with symmetric NTS auth | ~8,000/s estimated | x86-64 @ 2.5GHz | AES-SIV-CMAC-256 per packet |
| Server response (minimal) | ~100,000/s estimated | x86-64 @ 2.5GHz | No auth, no extension fields |
| Server with extension fields | ~20,000/s estimated | x86-64 @ 2.5GHz | NTS cookies appended |
| Burst receive (1000 packets) | ~200,000/s estimated | x86-64 @ 2.5GHz | Kernel socket backlog |

## E10. Discipline Cycle Latency

| Operation | Latency | Notes |
|-----------|---------|-------|
| adjtimex syscall | ~0.5 µs | LP64 syscall overhead |
| REF_SetReference (cold) | ~5 µs estimated | Full pipeline: clock estimates, offset check, sync status |
| SRC_SelectSource (4 sources) | ~10 µs estimated | Sorting, falseticker check, clustering |
| combine_sources (4 sources) | ~3 µs estimated | Weighted average of selected sources |
| Full discipline cycle (4 sources) | ~25 µs estimated | Receive → select → combine → ref → adjtimex |
| Full discipline cycle (32 sources) | ~200 µs estimated | O(n²) selection algorithm |

## E11. Memory Footprint

| Component | Memory | Notes |
|-----------|--------|-------|
| Source instance (per source) | ~2 KB | State, stats, auth context |
| Key store (100 keys) | ~16 KB | Key id → key data mapping |
| Client log (default limit 512K) | ~524 KB | LRU cache of client records |
| Source stats ring buffer (per source, 1024 samples) | ~32 KB | Sample history for regression |
| NTS cookie codec (per source) | ~1 KB | AEAD key material |
| NTP packet buffer (per socket) | ~1.2 KB | Extended: 48 + 1024 + MAC |
| Total idle (4 sources, no client log) | ~1.5 MB estimated | Binary + heap |
| Total with client log (512K limit) | ~2 MB estimated | |

## Measurement Methodology

- **Latency**: `clock_gettime(CLOCK_MONOTONIC_RAW)` before/after operation, 10,000 iterations median.
- **Throughput**: Counted operations over a 1-second window with `CLOCK_MONOTONIC`.
- **Memory**: `mallinfo` / `malloc_stats` at steady state, cross-checked with `/proc/self/status VmRSS`.
- **CPU**: `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` on the worker thread.

## Design Notes

- The packet receive path uses a 1200-byte buffer (matching chrony's `NTP_PACKET_SIZE` of 48 + 1024 + MAC).
- Source selection is O(n²) in the number of sources due to the falseticker detection algorithm (the
  intersection of confidence intervals requires pairwise comparison).
- NTS AEAD operations dominate per-packet cost when enabled; plain (unauthenticated) NTP is
  significantly cheaper.
- The adjtimex syscall is the most frequent OS boundary, called on every discipline cycle
  (typically every 1-64 seconds per source).
- Drift file writes are throttled to no more than once per `MAX_DRIFTFILE_AGE` (3600 seconds).
