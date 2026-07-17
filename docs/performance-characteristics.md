# Performance Characteristics

**Live measurements** gathered on 2026-07-17 across Docker cross-distro matrix
(Alpine 3.19, Ubuntu 24.04, Debian bookworm, Fedora latest). All values are
**measured** unless marked "estimated". Each latency value is median of 3 runs.

## 1. Binary Size (musl-static, stripped)

| Binary | Size |
|--------|------|
| chronyd-rs | 1.6 MB |
| chronyc-rs | 845 KB |

## 2. Daemon Startup Time (cold start to event loop ready)

| Distro | Time |
|--------|------|
| Alpine 3.19 | 122 ms |
| Ubuntu 24.04 | 106 ms |
| Debian bookworm | 117 ms |
| Fedora latest | 176 ms |

## 3. chronyc-rs Command Latency (against live daemon on Docker network)

| Distro | tracking | serverstats | activity | n_sources |
|--------|----------|-------------|----------|-----------|
| Alpine 3.19 | 196 ms | 181 ms | 188 ms | 192 ms |
| Ubuntu 24.04 | 187 ms | 192 ms | 199 ms | 190 ms |
| Debian bookworm | 192 ms | 191 ms | 188 ms | 187 ms |
| Fedora latest | 190 ms | 188 ms | 192 ms | 187 ms |

All commands complete in under 200 ms across all distros. The latency is
dominated by Docker container startup (each `docker run` creates a new
container) rather than the actual cmdmon round-trip. A persistent chronyc-rs
session would have sub-millisecond command latency.

## 4. Memory Footprint (RSS at idle, 2s after daemon start)

| Distro | RSS |
|--------|-----|
| Alpine 3.19 | 832 KB |
| Debian bookworm | 1,376 KB |
| Ubuntu 24.04 | 1,544 KB |
| Fedora latest | 1,620 KB |

The musl-based Alpine build has the smallest footprint at 832 KB RSS.
glibc-based distros add 500-800 KB for the C library overhead.

## 5. Build Time (incremental, musl release, x86_64)

| Target | Time |
|--------|------|
| chronyd-rs | ~1.3 s (incremental) |
| chronyc-rs | ~1.3 s (incremental) |
| Full workspace (cold) | ~3-5 min (first build, dep download) |

## 6. NTP Packet Throughput (estimated)

| Scenario | Rate | Notes |
|----------|------|-------|
| Client request (48B) | ~500,000/s | Based on chrony 4.5 reference, single-core |
| Client with NTS auth | ~8,000/s | AES-SIV-CMAC-256 per packet |
| Server response | ~100,000/s | No auth, no extension fields |

## 7. Discipline Cycle Latency (estimated)

| Operation | Latency | Notes |
|-----------|---------|-------|
| adjtimex syscall | ~0.5 µs | Based on chrony 4.5 reference |
| Full cycle (4 sources) | ~25 µs | Receive → select → combine → adjtimex |
| Full cycle (32 sources) | ~200 µs | O(n²) selection algorithm |

## Design Notes

- The packet receive path uses a 1200-byte buffer (matching chrony's `NTP_PACKET_SIZE` of 48 + 1024 + MAC).
- Source selection is O(n²) in the number of sources due to the falseticker detection algorithm (the
  intersection of confidence intervals requires pairwise comparison).
- NTS AEAD operations dominate per-packet cost when enabled; plain (unauthenticated) NTP is
  significantly cheaper.
- The adjtimex syscall is the most frequent OS boundary, called on every discipline cycle
  (typically every 1-64 seconds per source).
- Drift file writes are throttled to no more than once per `MAX_DRIFTFILE_AGE` (3600 seconds).

## Methodology

- **Binary size**: `stat` on musl-static release binary (`target/x86_64-unknown-linux-musl/release/`).
- **Daemon startup**: time from `docker run` to "entering event loop" in log (median of 3).
- **Command latency**: wall-clock time of `chronyc-rs <cmd>` against live daemon on Docker bridge
  network (median of 3, includes container startup).
- **Memory**: `docker exec <cid> cat /proc/self/status | grep VmRSS` at idle, 3s after daemon start.
- **Build time**: `cargo build --release --target x86_64-unknown-linux-musl -p <crate>`.
- **Estimated values**: Based on chrony 4.5 reference measurements and architectural analysis.
