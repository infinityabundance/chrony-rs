# Security policy

## Status

`chrony-rs` is a **forensic reconstruction** (Stage 6–7 — see
deployment-boundary.md). It **does** open NTP sockets, discipline the system clock
via adjtimex, accept control commands via cmdmon, and run as a daemon in lab
mode. It is **not** suitable for production time service without external
review. Do not deploy it as your sole time daemon in production.

The host-facing surface includes:

- NTP UDP socket I/O (`--lab-daemon` mode),
- cmdmon control protocol (all 73 commands),
- system-clock mutation (adjtimex step/slew/frequency),
- NTP packet encoding/decoding (panic-free on hostile input),
- chrony config file parsing (`--check-config`),
- Unix socket and signal handling.

## Reporting a vulnerability

If you find a memory-safety issue, a panic on untrusted input (e.g. a packet or
config that crashes the parser), or any boundary that fails *open* where it should
fail *closed*, please open a report. Include a minimal reproducer; for parser
crashes, the input bytes are enough.

## Scope reminders

- `unsafe` code count is currently **zero**; any future `unsafe` must be audited
  and documented (`docs/security-boundary.md`).
- No production-replacement claim is made. See `docs/deployment-boundary.md`.
