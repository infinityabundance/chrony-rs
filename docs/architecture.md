# Architecture

`chrony-rs` is organized so that the parts of chrony that can be reasoned about
*deterministically* are isolated from the parts that touch the host. This is not
a stylistic choice — it is the precondition for the forensic method, which
depends on replaying behavior without a real clock, real network, or privileges.

## Workspace layout

```
crates/
  chrony-rs-core   the deterministic time-discipline brain
  chronyd-rs       daemon/replay binary (offline & lab modes only today)
  chronyc-rs       control client & output-parity tool
```

The crate is kept lean; the GitHub repository carries the wider archaeology
archive (`docs/`, `reports/`, and — as campaigns land — `research/`).

## `chrony-rs-core` modules

| Module | Responsibility | Parity kind |
|--------|----------------|-------------|
| `ntp` | NTP wire format: packet + timestamp/short fixed-point | byte |
| `config` | lexer → model → parser → diagnostics | behavior |
| `report` | `chronyc` output rendering (`tracking` today) | byte (output) |
| `trace` | `chrony-rs-trace-v1` schema + structural validation | foundation |

Everything in `core` is total and side-effect-free — no file I/O, no sockets, no
clock reads — **with one documented exception**: [`nameserv`](../crates/chrony-rs-core/src/nameserv.rs)
performs hostname resolution via the system resolver (`getaddrinfo`), because
chrony's `allow`/`deny` parsing (`CPS_ParseAllowDeny`) resolves hostnames and that
branch is ported rather than deferred. Resolution is the single non-deterministic,
network-capable entry point; it is isolated in that one module, clearly labelled,
and nothing on the pure path calls it (its tests use only `localhost`/`.invalid`).
The rest of `core` stays deterministic, which keeps the unit tests reproducible and
lets the same code run under a simulated clock during replay.

## Trait boundaries (planned)

Host mutation will live behind narrow traits so the brain never depends on the
real environment. The intended seams (not yet all implemented) are:

```rust
trait SystemClock { /* now, step, slew, read/set frequency */ }
trait NetworkIo   { /* recv_ntp, send_ntp */ }
trait StateStore  { /* load/save drift */ }
trait ControlSocket { /* recv command, send response */ }
```

with three wirings:

```
real daemon:  RealSystemClock + UdpSockets + FileStateStore + UnixControlSocket
replay:       SimulatedClock  + TraceNetwork + MemoryStateStore + TraceControlSocket
oracle:       captured chronyd trace + chrony-rs replay + byte/behavior compare
```

Only the replay wiring is on the near horizon; the real-daemon wiring is gated
behind the deployment ladder (`deployment-boundary.md`).

## Why not one big async daemon

A single opaque async application would make behavior non-reproducible and hide
state. We prefer an explicit event loop and typed state transitions so that every
decision (sample accept/reject, source select, step vs slew) is observable and
can be pinned to a court. Determinism first; performance and concurrency later,
and only where measured.
