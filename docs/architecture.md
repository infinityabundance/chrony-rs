# Architecture

`chrony-rs` is organized so that the parts of chrony that can be reasoned about
*deterministically* are isolated from the parts that touch the host. This is not
a stylistic choice — it is the precondition for the forensic method, which
depends on replaying behavior without a real clock, real network, or privileges.

## Workspace layout

```
crates/
  chrony-rs-core   the deterministic time-discipline brain (~50+ ported modules)
  chrony-rs-io     real OS I/O layer (libc syscall wrappers)
  chronyd-rs       daemon/replay binary (lab daemon, replay, --cmdmon)
  chronyc-rs       control client & output-parity tool
  chrony-rs        facade crate re-exporting chrony-rs-core
  xtask            build/automation (doc generation, freshness gate, comparative diagnostics)
  fuzz             fuzz targets (packet-decode, cmdmon-validate, config-parse, ntp-header)
```

The crate is kept lean; the GitHub repository carries the wider archaeology
archive (`docs/`, `reports/`, and — as campaigns land — `research/`).

## Deterministic-core principle

Everything in `chrony-rs-core` is total and side-effect-free — no file I/O, no
sockets, no clock reads — **with one documented exception**:
[`nameserv`](../crates/chrony-rs-core/src/nameserv.rs) performs hostname resolution
via the system resolver (`getaddrinfo`), because chrony's `allow`/`deny` parsing
(`CPS_ParseAllowDeny`) resolves hostnames and that branch is ported rather than
deferred. The rest of `core` stays deterministic, which keeps the unit tests
reproducible and lets the same code run under a simulated clock during replay.

## Trait boundaries (implemented)

Host mutation lives behind narrow traits so the brain never depends on the
real environment. The implemented seams are:

```rust
trait SystemClock  { /* now, step, slew, read/set frequency — via adjtimex */ }
trait NetworkIo    { /* recv_ntp, send_ntp — via NTP/UDP sockets */ }
trait StateStore   { /* load/save drift — via atomic temp+rename files */ }
trait ControlSocket{ /* recv command, send response — via cmdmon UDP */ }
```

with three wirings:

```
real daemon:  RealSystemClock + UdpSockets + FileStateStore + UnixControlSocket
replay:       SimulatedClock  + TraceNetwork + MemoryStateStore + TraceControlSocket
oracle:       captured chronyd trace + chrony-rs replay + byte/behavior compare
```

All four traits are wired in the `--lab-daemon` mode.

## Why not one big async daemon

A single opaque async application would make behavior non-reproducible and hide
state. We prefer an explicit event loop and typed state transitions so that every
decision (sample accept/reject, source select, step vs slew) is observable and
can be pinned to a court. Determinism first; performance and concurrency later,
and only where measured.
