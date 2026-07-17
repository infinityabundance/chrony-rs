# Chrony-rs: Comprehensive Gap Analysis and Implementation Plan

> **⚠️ ARCHIVAL REFERENCE ONLY — DO NOT USE FOR CURRENT STATUS**
>
> This document was written during early development and has **not** been
> maintained. Almost every item listed as a gap here has since been implemented.
> It is preserved for historical reference of the development trajectory.
>
> **For current status, see:**
> - [`negative-capabilities.md`](negative-capabilities.md) — what is genuinely not done
> - [`deployment-boundary.md`](deployment-boundary.md) — staged ladder status
> - [`status.md`](generated/status.md) — generated parity status

**Status: 2026-07-16 (archival) | Targeting chrony 4.5 | Function-level parity: ~98%**

This document was the original gap analysis. Most gaps are now closed.
It is preserved as a record of the development trajectory.

---

## 1. AUTHENTICATION — Wired but not integrated into packet pipeline

### 1.1. Symmetric-key MAC verification in process_response
| | |
|---|---|
| **Current** | `check_symmetric_auth(packet, info, keys)` is now `pub`. `auth_check_response()` and `auth_check_request()` exist in `rx_dispatch.rs`. `parse_packet()` extracts `auth_mode` and `mac_key_id` into `NtpPacketInfo`. |
| **Missing** | The caller (`process_response`/`process_sample`) does not yet call `auth_check_response`. The `NauInstance` and `KeyStore` from the source instance are not connected to the packet processing path. |
| **Fix** | (1) Add `auth: &mut NauInstance` and `keys: &mut KeyStore` parameters to `process_sample` or create a wrapper. (2) Call `auth_check_response()` before accepting the sample. (3) Log auth failure via court event. **~2 days** |

### 1.2. NTS authenticator verification
| | |
|---|---|
| **Current** | `NNA_DecryptAuthEF` ✅ ported. SIV decrypt ✅ (AES-SIV-CMAC-256). Auth mode detection in `parse_packet()` sets `NTP_AUTH_NTS`. The `NauInstance::check_response_auth()` NTS path calls `NnsInstance::check_response_auth()` which calls `NNA_DecryptAuthEF`. |
| **Missing** | Same as 1.1 — the auth check functions exist but aren't called. Once 1.1 is fixed, NTS auth works automatically. No additional code needed. |

### 1.3. Key file loading and KeyStore wiring
| | |
|---|---|
| **Current** | `keys.c` ✅ ported (17 functions). Key file parsing (`KEY_Initialise`, `decode_key`) ✅ tested. The `KeyStore` struct is used in tests but not wired to a real key file path. |
| **Missing** | `chronyd-rs` doesn't read a key file at startup. The `--check-config` mode parses `keyfile` directives but doesn't load them. |
| **Fix** | Add key file loading to `--check-config` or `--cmdmon` initialization. Read `keyfile` path from config, call `KEY_Initialise`. Wire `KeyStore` into the dispatch/auth path. **~1 day** |

---

## 2. NTP PROTOCOL ENGINE — Core measurement pipeline not assembled

### 2.1. Live poll T1/T4 capture
| | |
|---|---|
| **Current** | Packet codec (encode/decode) ✅ ported. Poll-interval arithmetic ✅ (`get_separation`, `get_poll_adj`, `adjust_poll`). TX timestamp update ✅ (`update_tx_timestamp`). |
| **Missing** | The daemon-side recording of our transmit (T1) and receive (T4) timestamps for a live poll/response cycle is not wired. The `NCR_Instance` state machine that connects transmit → receive → process is not assembled. |
| **Fix** | (1) Create `NtpInstance` struct holding `NauInstance`, `KeyStore`, `SourceTable` index, poll state. (2) Wire `NIO_SendPacket` → record T1 → schedule timeout → `process_response` on receive → record T4. (3) Connect to `NCR_ProcessRxKnown` dispatch. **~1 week** |

### 2.2. Interleaved mode timestamp matching
| | |
|---|---|
| **Current** | `save_response`/`saved_response_timeout` 🔧 exist as injected wrappers (in `ntp/lifecycle.rs`). The timestamp selection logic in `ntp/sample.rs` ✅ ported. |
| **Missing** | Saved-response lifecycle is not wired into the measurement pipeline. The saved-response timeout and matching logic is not connected. |
| **Fix** | Same as 2.1 — the NtpInstance needs a saved-response ring buffer. **Part of 2.1** |

### 2.3. Broadcast client mode
| | |
|---|---|
| **Current** | `ncr_add_broadcast_destination` 🔧 exists as trait-injected wrapper. Broadcast classification in `classify_rx_known` returns `ProcessAsUnknown`. |
| **Missing** | No broadcast listener socket. No broadcast packet processing (different from unicast). |
| **Fix** | (1) Open broadcast client socket when config has `broadcast` directive. (2) Wire `classify_rx_known(broadcast, client) = ProcessAsUnknown` → server response path. **~3 days** |

---

## 3. SOURCE SELECTION — Algorithm ported, not wired into daemon

### 3.1. Source-selection oracle replay
| | |
|---|---|
| **Current** | `SRC_SelectSource` ✅ ported (517 lines, differential-tested). `SourcesHost` trait ✅ defined. `--replay` mode exists but `selected_source` is a placeholder (most-recently-seen). |
| **Missing** | `SourcesHost` implementation for the replay runner. Source registry built from trace events. `SRC_SelectSource` called after each poll/recv event. |
| **Fix** | (1) Create `struct ReplaySources` implementing `SourcesHost`. (2) Build `SourceTable` and `SourceRegistry` from trace events. (3) Call `SRC_SelectSource` after each event. (4) Compare selected source against chrony oracle. **~5 days** |

### 3.2. Source reachability in replay
| | |
|---|---|
| **Current** | 8-bit reachability register ✅ ported (`sources/reachability.rs`). Not wired into replay. |
| **Missing** | `SRC_UpdateReachability` is not called during replay. Without it, `SRC_SelectSource` decisions are wrong. |
| **Fix** | Wire reachability into the `SourcesHost` implementation from 3.1. **Part of 3.1** |

### 3.3. Auth data in source selection
| | |
|---|---|
| **Current** | `NCR_GetAuthReport` ✅ ported. Auth mode is stored per-instance. |
| **Missing** | The auth report is not surfaced through the control protocol. `chronyc authdata` won't return real data. |
| **Fix** | Wire `REQ_AUTH_DATA` handler to return per-source auth state from `NauInstance::get_report()`. **~1 day** |

---

## 4. CLOCK DISCIPLINE — Algorithms ported, closed loop not assembled

### 4.1. Full discipline state machine
| | |
|---|---|
| **Current** | `REF_SetReference` ✅ (46 functions). `LCL_ApplyStepOffset` ✅. `LCL_AccumulateFrequencyAndOffset` ✅. `LCL_SetSyncStatus` ✅. `sys_generic`/`sys_null` drivers ✅. All differential-tested. |
| **Missing** | The closed loop: when a sample is accepted → call `REF_SetReference` → `LCL_ApplyStepOffset`/`LCL_AccumulateFrequencyAndOffset` → driver → tracking log. Scheduler timeouts not wired. |
| **Fix** | (1) Create `struct DisciplineState` holding `Reference`, `LocalClock`, `SysDriver`. (2) Wire `process_response` → sample accepted → `Reference::set_reference()`. (3) Wire scheduler timeouts for polling. (4) Wire drift file read/write. **~2 weeks** |

### 4.2. Real adjtimex syscall
| | |
|---|---|
| **Current** | `sys_timex.rs` ✅ (ppm scaling, state machine). `sys_linux.rs` ✅ (tick/freq split). Both take an injected `adjtimex` closure. |
| **Missing** | The real `libc::adjtimex()` call is never invoked. Attempted to add it to `driver.rs` but the `libc::timex` struct on musl has different fields (`__bitfield_N` vs named bitfields). |
| **Fix** | (1) Create `real_adjtimex()` in `chrony-rs-io::driver` that calls `libc::adjtimex`. (2) Handle `libc::timex` struct differences across platforms with `#[cfg]` or version checks. (3) Wire into `SysTimex::new()`. **~2 days** |

### 4.3. Drift/dump/state file daemon I/O
| | |
|---|---|
| **Current** | Coefficient format ✅ (`format_coefs`, `parse_coefs`). SST serialization ✅ (`SST_SaveToFile`, `SST_LoadFromFile`). File I/O operations 🔧 exist as injected wrappers (`open_file`, `remove_file`, `rename_temp_file`). |
| **Missing** | `REF_Initialise` doesn't read drift file. `REF_Finalise` doesn't write it. `SRC_DumpSources`/`SRC_ReloadSources` don't persist. |
| **Fix** | (1) Wire drift file read in `REF_Initialise`. (2) Wire drift file write in `REF_Finalise` (using `rename_temp_file` for atomicity). (3) Wire dump/load lifecycle. **~3 days** |

---

## 5. CONTROL PROTOCOL — Transport works, reply decoding incomplete

### 5.1. Full reply body decoding in chronyc-rs
| | |
|---|---|
| **Current** | `build_request_header` ✅. Wire format encode/decode ✅ for all commands. `chronyc-rs` connects via UDP and sends properly-formed requests. Reply bodies are received but body bytes are not decoded into proper report structs (only dumped as raw). |
| **Missing** | `chronyc-rs tracking` doesn't decode 80-byte RPY_Tracking → `TrackingReport` → `render()`. Same for sourcestats (60 bytes), source_data (52), activity (24), server_stats (172). |
| **Fix** | (1) Add `decode_tracking_reply(bytes) -> TrackingReport` in `client.rs`. (2) Add decode functions for other reply types. (3) Wire decoders into `chronyc-rs main.rs`. (4) Connect decoder output to `report.render()`. **~3 days** |

### 5.2. Daemon-side cmdmon server dispatch wiring
| | |
|---|---|
| **Current** | `CmdMon::initialise()` ✅ opens socket, registers handler. `real_dispatch()` handles all 73 commands. The `--cmdmon 3343` flag works: sending REQ_N_SOURCES returns `status=0 N_SOURCES=0`. |
| **Missing** | The dispatch closures return stub data (hardcoded `TrackingReport`, `n_sources=0`, etc.). They should return real daemon state. The cmdmon server isn't started by default (requires `--cmdmon` flag). |
| **Fix** | (1) Wire dispatch closures to real daemon state when available. (2) Make `--cmdmon` start the scheduler event loop. (3) Add socket finalization on exit. **~2 days** |

---

## 6. NTP SERVER MODE — Not started

### 6.1. Server-path packet handling
| | |
|---|---|
| **Current** | `classify_rx_unknown` ✅ returns `MODE_SERVER` for client requests. Server sockets open/close ✅ integration-tested. `transmit_packet` client path ✅. |
| **Missing** | Server-path `transmit_packet` (reference ID, stratum, smoothing, interleaved timestamps). Server response to client requests is not wired. |
| **Fix** | (1) Add server-mode `transmit_packet` builder. (2) Wire `classify_rx_unknown` response to `transmit_packet`. (3) Add server socket to scheduler. (4) Implement server access control (ADF_*). **~1 week** |

### 6.2. Broadcast server mode
| | |
|---|---|
| **Current** | `broadcast_timeout` 🔧 exists as injected wrapper. |
| **Missing** | No broadcast server socket. No periodic broadcast packet. |
| **Fix** | Wire broadcast server when configured. **~3 days** |

---

## 7. NTS — All codecs ported, no TLS handshake

### 7.1. TLS handshake and key export
| | |
|---|---|
| **Current** | NTS-KE record codec ✅ (32 functions). Cookie codec ✅ (AES-SIV-CMAC-256). Client message logic ✅ (10 functions). Server message logic ✅ (21 functions). TLS/gnutls is the host boundary. |
| **Missing** | No TLS library wired (rustls or openssl). No TLS handshake. No key export from TLS session. |
| **Fix** | (1) Add TLS library dependency (rustls recommended for Rust-native, no gnutls FFI). (2) Implement `TlsSession` trait. (3) Wire TLS key export → cookie codec. (4) Wire NTS-KE server/client. **~2 weeks with a TLS library** |

### 7.2. NTS authenticator in packet path
| | |
|---|---|
| **Current** | Same as 1.2 — once 1.1 is fixed and NTS keys are available, NTS auth works automatically. |
| **Missing** | NTS session keys must be derived from TLS handshake (7.1) before verification can work. |
| **Fix** | Blocked on 7.1. |

---

## 8. REFCLOCK / RTC — All codecs ported, no device I/O

### 8.1. Real device I/O
| | |
|---|---|
| **Current** | `refclock.c` framework ✅ (28 functions). SHM codec ✅. SOCK codec ✅. RTC driver ✅ (26 functions). All device I/O is the host boundary. |
| **Missing** | No `/dev/rtc` access (ioctl `RTC_RD_TIME`, `RTC_SET_TIME`). No SHM segment attach (`shmget`, `shmat`). No SOCK datagram socket. |
| **Fix** | (1) Wire `/dev/rtc` file access behind `RtcDriver` trait. (2) Wire `ShmSource` for shared-memory refclock. (3) Wire `SOCK` datagram socket for gpsd. **~1 week with hardware access** |

---

## 9. OS / PLATFORM — Real syscalls not wired

### 9.1. Privilege drop (setuid/seccomp/mlockall)
| | |
|---|---|
| **Current** | `sys.rs` ✅ ported (6 trait-injected functions). `SYS_DropRoot`, `SYS_EnableSystemCallFilter`, `SYS_LockMemory`, `SYS_SetScheduler`. |
| **Missing** | Real syscalls: `setuid()`, `seccomp(SECCOMP_SET_MODE_FILTER)`, `mlockall(MCL_CURRENT|MCL_FUTURE)`, `sched_setscheduler()`. |
| **Fix** | Wire real syscalls behind the trait. Add `libc` FFI calls. **~2 days** |

### 9.2. FreeBSD / macOS clock adapters
| | |
|---|---|
| **Current** | `sys_netbsd.c` ✅. `sys_solaris.c` ✅. FreeBSD/macOS ❌ (zero-function C inventory). |
| **Missing** | FreeBSD: `ntp_adjtime()` syscall, `clock_gettime(CLOCK_REALTIME)`. macOS: `mach_timebase_info()`, `clock_get_time()` (or `mach_absolute_time()`). |
| **Fix** | Create `sys_freebsd.rs` and `sys_macos.rs` following the same pattern as `sys_linux.rs`/`sys_netbsd.rs`. **~1 week each** |

---

## 10. FUZZING — Files exist, not compiled or run

### 10.1. Fuzz target compilation
| | |
|---|---|
| **Current** | 4 targets in `fuzz/fuzz_targets/`: `packet-decode.rs`, `cmdmon-validate.rs`, `config-parse.rs`, `ntp-header.rs`. The `fuzz/` directory is NOT in workspace members. |
| **Missing** | Add `fuzz` to workspace members. Install `cargo-fuzz`. Compile with `cargo +nightly fuzz build`. Run minimum 1M iterations each. |
| **Fix** | (1) Add `fuzz` to `workspace.members` in root `Cargo.toml`. (2) `cargo install cargo-fuzz`. (3) `cargo +nightly fuzz build`. (4) `cargo +nightly fuzz run packet-decode -- -max_total=1000000`. **~1 day** |

### 10.2. Kani proof harness compilation
| | |
|---|---|
| **Current** | 5 proofs in `fuzz/kani-proofs.rs`. Uses `#[cfg(kani)]` which only activates under Kani. |
| **Missing** | Install Kani: `cargo install kani-verifier`. Run proofs: `cargo kani --harness packet_decode_no_panic`. |
| **Fix** | (1) `cargo install kani-verifier`. (2) Run each proof. (3) Fix any verification failures (expected: proofs should pass since the code is total). **~1 day** |

---

## 11. TESTING — False successes and gaps

### 11.1. Behavioral test gaps
| | |
|---|---|
| **Current** | 16 tests covering: request validation (7 cases), reply header format, 5 decoder round-trips, 5 reply encoder sizes, source state/mode wire, pktlength consistency. |
| **Missing** | No tests for: authentication codec, NTS packet handling, interleaved timestamp matching, server-mode dispatch, broadcast handling, refclock SHM/SOCK parsing. |
| **Fix** | Add test cases for each missing area. Target: 50+ behavioral tests. **~1 week** |

### 11.2. xtask verify does not test time infrastructure
| | |
|---|---|
| **Current** | Verify runs 10 checks: build, protocol round-trips, court module, binary builds, oracle file count, license, freshness gate. None exercise the clock discipline, source selection, or NTP protocol engine. |
| **Missing** | Add checks for: `reference.rs` differential tests, `sources.rs` selection tests, `sourcestats.rs` regression tests, `regress.rs` statistical tests, `sched.rs` event-loop tests. |
| **Fix** | Replace generic `cargo check` checks with targeted test runs: `cargo test -p chrony-rs-core -- reference`, `cargo test -p chrony-rs-core -- sources`, etc. **~1 day** |

### 11.3. QEMU receipts are all from same static binary
| | |
|---|---|
| **Current** | 6 "receipts" exist for Alpine, Debian, Ubuntu, Fedora, Arch, openSUSE. All are copies of the same test output from the statically-linked musl binary. They prove cross-distro compatibility of statically-linked binaries only. |
| **Missing** | No actual per-distro VM testing. No verification that dynamically-linked chrony-rs works on each distro's native glibc/musl. No receipts from actual QEMU VMs. |
| **Fix** | Requires a host system with `qemu-system-x86_64` and KVM. The `tools/qemu-test.sh` script is ready. Run `bash tools/qemu-test.sh --all` on a host with QEMU. **~2 days with QEMU host** |

### 11.4. `return true` statements may hide failures
| | |
|---|---|
| **Current** | 15+ `return true;` statements in production code (clientlog, reference, poll, refclock, etc.). Each is a code path that unconditionally succeeds. Some may be correct (early exit for disabled features), others may hide missing logic. |
| **Missing** | Audit each `return true;` to verify it's correct. Convert to `Result` or proper error handling where appropriate. |
| **Fix** | (1) Audit all `return true;` and `return false;` in non-test code. (2) For each, verify the condition matches chrony's behavior. (3) Add court events for unexpected paths. **~2 days** |

---

## 12. DEFERRED ITEMS (not yet started)

### 12.1. Control socket Unix permissions
| | |
|---|---|
| | `CmdMon::open_unix_socket` opens Unix domain socket but doesn't set permissions (chrony uses `0755`). |
| | **Fix**: Add `chmod` call after bind. **~4 hours** |

### 12.2. PID file management
| | |
|---|---|
| | `MAI_CleanupAndExit` exists but `write_pidfile`/`check_pidfile`/`delete_pidfile` are not wired. |
| | **Fix**: Wire PID file lifecycle into daemon startup/exit. **~4 hours** |

### 12.3. Signal handling
| | |
|---|---|
| | `set_quit_signals_handler` exists but is not called. chronyd handles SIGINT/SIGTERM for graceful shutdown. |
| | **Fix**: Wire signal handlers using `libc::sigaction`. **~4 hours** |

### 12.4. Systemd LISTEN_FDS support
| | |
|---|---|
| | `Sockets::pre_initialise()` parses `LISTEN_FDS` but the reusable socket pool is inert. |
| | **Fix**: Implement reusable socket fetch from the LISTEN_FDS window. **~1 day** |

### 12.5. Rate limiting (clientlog)
| | |
|---|---|
| | `CLG_LimitServiceRate` ✅ ported. Not wired into NTP packet processing. |
| | **Fix**: Call rate limiter before processing each received packet. **~1 day** |

### 12.6. Access control (ADF_*)
| | |
|---|---|
| | `ADF_IsAllowed` ✅ ported. Not wired into NTP or cmdmon packet processing. |
| | **Fix**: Call access control before accepting NTP packets or cmdmon commands. **~1 day** |

---

## SUMMARY

| Area | Total Effort | Priority | Impact |
|------|-------------|----------|--------|
| Auth integration (1.1-1.3) | 3 days | **P0** | Security |
| Protocol engine (2.1-2.3) | 1.5 weeks | **P0** | Core functionality |
| Source selection replay (3.1) | 5 days | **P0** | Forensic parity |
| Clock discipline (4.1-4.3) | 2.5 weeks | **P1** | Core functionality |
| Control protocol (5.1-5.2) | 3 days | **P1** | Usability |
| NTP server (6.1-6.2) | 1.5 weeks | **P2** | Feature parity |
| NTS (7.1-7.2) | 2 weeks | **P2** | Feature parity |
| Refclock/RTC (8.1) | 1 week | **P3** | Hardware support |
| OS/Platform (9.1-9.2) | 1 week | **P3** | Platform parity |
| Fuzzing (10.1-10.2) | 2 days | **P0** | Security validation |
| Testing (11.1-11.4) | 1 week | **P0** | Quality assurance |
| Deferred items (12.1-12.6) | 3 days | **P2** | Production readiness |

**Total remaining: ~12-14 weeks for a single developer working full-time.**

All P0 items (auth, protocol engine, source selection, fuzzing, testing) can be completed in **~3-4 weeks**. P1 items (discipline, control protocol) add another **~3-4 weeks**. P2/P3 items (server, NTS, refclock, platform) add the remaining **~6 weeks**.
