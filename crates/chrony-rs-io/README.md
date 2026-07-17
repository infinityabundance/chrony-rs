# chrony-rs-io

Real OS I/O layer for chrony-rs — a faithful port of chrony's `socket.c` syscall layer,
the `sched.c` `select()` event-loop driver, the `ntp_io.c` NTP socket path, and the
`privops.c` fork+socketpair privileged-helper transport.

This crate contains the **only** `unsafe` code in the chrony-rs workspace (aside from
`chronyd-rs`'s daemonisation and signal handling). Every `unsafe` block is a single
`libc` FFI call — syscall wrapper, device ioctl, or shared-memory access — annotated
with a `// SAFETY:` justification.

## Contents

- `socket.rs` — UDP/TCP socket creation, binding, connection, send/recv with chrony's
  exact option sequence (IP_PKTINFO, DSCP, SO_TIMESTAMPING, etc.)
- `driver.rs` — Real-time clock access (`clock_gettime`, `adjtimex`) and file I/O
  (`read_drift_file`, `write_drift_file`)
- `ntp_io.rs` — NTP packet send/receive with timestamp extraction
- `cmdmon.rs` — Command-response Unix socket (`send_reply`, `send_error`)
- `privops.rs` — Privilege-separation helper (`fork()` + `socketpair()` IPC)
- `logging.rs` — Syslog integration (`openlog`, `syslog`, `closelog`)
- `config_loader.rs` — Filesystem-based config loading with `include`/`confdir` expansion
- `key_io.rs` — Key file I/O (`KEY_Initialise`, `KEY_ReadFile`, `KEY_Reload`)
- `rtc_linux_io.rs` — Linux RTC device I/O (`/dev/rtc` ioctl wrappers)
- `shm_io.rs` — POSIX shared-memory I/O for the SHM refclock driver
- `sock_io.rs` — Unix-domain socket I/O for the SOCK refclock driver

## Testing

Integration tests probe real devices and kernel interfaces, skipping gracefully when
unavailable. Run with:

```sh
cargo test -p chrony-rs-io
```

## Safety

This crate uses `unsafe` for FFI calls to `libc`. Each block is justified with a
`// SAFETY:` comment. The `chrony-rs-core` crate (which this depends on) is
`unsafe`-free.


## crates.io

Published at [crates.io/crates/chrony-rs-io](https://crates.io/crates/chrony-rs-io).
Part of the [chrony-rs](https://crates.io/crates/chrony-rs) workspace.
