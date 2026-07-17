# Security boundary

chrony is privileged, network-facing, clock-mutating infrastructure. This document
records the trust boundaries `chrony-rs` reasons about and the current posture at
each. Most are not yet *crossed* (no daemon, no clock mutation), though the real
UDP/TCP/Unix socket layer is now implemented (`chrony-rs-io`); every boundary is
documented so it is never crossed silently.

## Unsafe / FFI

**`unsafe` count: 127.** Total `unsafe` blocks across workspace: 172.

| Crate | Count | Notes |
|-------|-------|-------|
| `chrony-rs-io` | 113 | Real OS I/O layer (socket, select, clock, ioctl, etc.) — all libc FFI |
| `chronyd-rs` | 30 | Signal handlers, process control (fork/setsid), clock discipline syscalls |
| `chrony-rs-core` | 0 | Verified — `grep -rn "unsafe" crates/chrony-rs-core/src` → 0 matches |
| `chrony-rs` (facade) | 0 | `#![forbid(unsafe_code)]` |
| `chronyc-rs` | 0 | |

- **`chrony-rs-io`** contains ~113 `unsafe` blocks: a faithful port of chrony's
  `socket.c` syscall path, the `sched.c` `select()` event-loop driver, the
  `ntp_io.c` NTP socket path, and the `privops.c` fork+socketpair privileged-
  helper transport.
  `chrony-rs-core` — every byte codec, all discipline math, the whole
  differential-tested surface — remains **`unsafe`-free**, which is the invariant
  that matters: untrusted-input parsing never touches `unsafe`.
- Why it exists: making the actual `socket`/`bind`/`connect`/`sendmsg`/`recvmsg`/
  `setsockopt`/`getsockopt`/`fcntl`/`close`/`select`/`clock_gettime` syscalls
  requires `libc` FFI, which is `unsafe` by definition. Each block is a single
  syscall or `errno` access,
  annotated with a `// SAFETY:` note, operating only on file descriptors the layer
  itself owns and on buffers that outlive the call. No `unsafe` block parses
  untrusted bytes — the received control/message bytes are handed to the
  `unsafe`-free `chrony-rs-core::socket` cmsg/sockaddr codecs for decoding.
- **`chronyd-rs`** contains ~30 `unsafe` blocks for signal handlers (`libc::write`
  in `extern "C" fn`), daemonisation (`libc::fork`/`setsid`/`close`/`dup2`),
  and clock discipline syscalls (`clock_gettime`, `adjtimex`, `mlockall`,
  `sched_setscheduler`, `setuid`/`setgid`).
- `chrony-rs-core`, `chronyc-rs`, and `chrony-rs` (the facade crate has
  `#![forbid(unsafe_code)]`) contain **zero** `unsafe` blocks.
- How it is verified: because syscalls cannot be differential-unit-tested against
  the C, the `chrony-rs-io` layer is covered by **kernel-integration tests** on
  real loopback sockets (`crates/chrony-rs-io/tests/udp.rs`) — the open→bind→
  connect→send→recv round-trip, `IP_PKTINFO` destination recovery, option
  set/get, family gating, and the receive-error path.
- Verify the boundary with: `grep -rL "unsafe" ...` — expected: matches **only**
  under `crates/chrony-rs-io/src`, never under `crates/chrony-rs-core/src`
  (`CHRONY.SECURITY.1`).

## Untrusted inputs and current handling

| Input | Trust | Current handling |
|-------|-------|------------------|
| NTP packet bytes | untrusted | total decode, no panic; too-short rejected (`CHRONY.PACKET.8` / `CHRONY.SECURITY.2`); fuzz-tested via cargo-fuzz targets (`packet-decode`, `ntp-header`) |
| config file | semi-trusted (operator) | fails closed on read error; typed diagnostics; `include` glob expansion with `MAX_INCLUDE_LEVEL=10` recursion guard; line length limit `MAX_LINE_LENGTH=2047` |
| replay trace JSON | semi-trusted | schema + monotonic-order validated before use; SHA-256 pinned expectations |
| tracking fixture JSON | semi-trusted | parsed with typed errors; bad input → exit 1 |
| control commands | untrusted | **not yet accepted** (no live socket dispatching real handlers; transport layer validates request framing via `validate_request`) |
| refclock/RTC devices | untrusted | **not yet accessed** (refclock framework ported; SHM/SOCK codecs ported; no device I/O) |
| NTS key material | secret | **not yet handled** (NTS-KE record/cookie codecs ported; no TLS key export or persistent key store) |
| cmdmon request bytes | untrusted | length/pkt-type/reserved/version/command validated by `validate_request`; out-of-range → drop or error reply. Decoders for 20+ command types are byte-exact differential-tested. |

## Panic policy

- **Library code in `chrony-rs-core` does not panic on input.** Parsing and decoding
  return `Result` or `Option`. The few `expect(...)` calls in the packet decoder
  are guarded by a prior length check and carry messages explaining why they cannot
  fire; they are invariants, not input validation.
- **Scheduler panics removed.** The 3 `panic!()` calls in `sched.rs` (invalid
  timeout id, infinite loop guard, nothing-to-do guard) have been converted to
  graceful `return`/`break` — matching chrony's behavior.
- **Config parser panics removed.** The 6 `panic!()` calls in `config/parser.rs`
  and `util.rs` (unknown family, unexpected mode, type mismatch) have been
  converted to safe fallback values (`IpAddr::Unspec`, `0`, `0.0`, `""`).
- **Report formatter panics removed.** The 6 `panic!()` calls in `report.rs`
  (argument type mismatch) have been converted to safe defaults.
- Remaining `unreachable!()` calls (14 instances) guard match arms that cannot be
  reached by construction (validated enum values, crypto-algorithm dispatch).
  Each is documented with a comment explaining the invariant.

## Process boundaries (planned, not implemented)

The **UDP socket layer** (`chrony-rs-io`) is now implemented for real (open/bind/
connect/send/recv with chrony's exact option sequence), contained to that crate
and integration-tested on loopback. The **privilege-separation helper**
(`chrony-rs-io::privops`) is implemented with real `fork()` + `socketpair()` IPC
and kernel-integration-tested.

The following remain **deferred**:

- Privilege drop (setuid/setgid/capabilities) — interface ported in `sys.rs`,
  real syscall execution is the host boundary
- Linux capabilities (`CAP_NET_RAW`, `CAP_SYS_TIME`, etc.)
- seccomp system-call filtering — interface ported in `sys.rs`
- chroot/jail
- control-socket Unix permissions (0755 on `/var/run/chrony`)
- `SO_BINDTODEVICE` (needs `CAP_NET_RAW`)
- systemd `LISTEN_FDS` socket inheritance
- Temp/state file handling (atomic writes via `rename_temp_file`)
- Resource-exhaustion limits (`MAX_SOURCES=65536`, `MAX_FILELOGS=6`,
  `MAX_INCLUDE_LEVEL=10` enforced)

No production-mode default exists; the daemon will refuse unsafe production mode
unless explicitly enabled (`CHRONY.SECURITY.7`).

## Cryptographic boundaries

- **MD5 hash:** Fully ported (RFC 1321 test vectors + differential-tested against
  chrony's compiled `md5.c` for all message lengths 0..130). Used for NTP
  symmetric-key authentication.
- **AES-CMAC:** Ported (RFC 4493, NIST SP 800-38B, differential-tested against
  compiled `cmac_nettle.c`). Used for NTP extension-field authentication.
- **AES-SIV-CMAC-256:** Ported (RFC 5297, differential-tested against compiled
  `siv_nettle_int.c`). Used for NTS AEAD.
- **AES block cipher:** Ported from FIPS-197 KAT (dependency-free Rust
  implementation).
- **Randomness:** Host boundary. The scheduler's timeout jitter uses a seeded
  xorshift64 PRNG. Cryptographic randomness (`UTI_GetRandomBytes`) is injected.
- **NTS key derivation:** Not wired. The TLS exporter (gnutls) is the host
  boundary; the cookie codec (NKS_GenerateCookie/NKS_DecodeCookie) is fully
  ported and composes the real AES-SIV-CMAC-256.

## Reporting

See `SECURITY.md` at the repository root.
