# Thread Safety Analysis

chrony-rs is a **single-threaded** time daemon. All time-critical code runs
in the main event loop thread. The design is:

## Thread model

- **Main thread**: Event loop (scheduler), NTP I/O, clock discipline, cmdmon
- **NTS-KE helper**: TLS handshake (runs in a separate thread/process)
- **Signal handlers**: Run in signal context (must be async-signal-safe)

## Shared state protection

- `QUIT` flag: `AtomicBool` — safe for signal handler → main thread
- `SCHEDULE_RELOAD` flag: `AtomicBool` — safe for SIGHUP handler → main thread
- NTP socket: Only accessed from main thread — no synchronization needed
- Drift file: Written only at shutdown — no concurrent access

## Unsafe code audit

Total `unsafe` blocks across workspace: ~143.

| Crate | Count | Notes |
|-------|-------|-------|
| `chrony-rs-io` | ~113 | All libc FFI syscall wrappers (socket, select, clock, ioctl, etc.) |
| `chronyd-rs` | ~30 | Signal handlers, process control (fork/setsid), clock discipline syscalls |
| `chrony-rs-core` | 0 | Verified — `grep -rn "unsafe" crates/chrony-rs-core/src` → 0 matches |
| `chrony-rs` (facade) | 0 | `#![forbid(unsafe_code)]` |
| `chronyc-rs` | 0 | |

The `chrony-rs-io` blocks are all syscall wrappers:
- `libc::adjtimex()` — safe (kernel interface, single-threaded)
- `libc::ioctl()` — safe (device interface, single-threaded)
- `libc::sendto()`/`recvfrom()` — safe (socket interface, single-threaded)
- `libc::open()`/`close()` — safe (file interface, single-threaded)
- `libc::signal()` — safe (signal interface, only called once at startup)
- `libc::setuid()`/`setgid()` — safe (privilege drop, only called once)

No data races, no concurrency, no reentrancy issues.
