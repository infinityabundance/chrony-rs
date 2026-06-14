# Security policy

## Status

`chrony-rs` is a **forensic reconstruction in early development** (Stage 1–2). It
does **not** discipline a real clock, open network sockets, accept control
commands, or run as a privileged daemon. It is **not** suitable for production
time service. Do not deploy it as your time daemon.

Because the host-facing surface is intentionally absent today, the live attack
surface is limited to input parsing of:

- NTP packet bytes (decode is total and panic-free),
- chrony config files (`--check-config`),
- replay traces and tracking fixtures (JSON).

## Reporting a vulnerability

If you find a memory-safety issue, a panic on untrusted input (e.g. a packet or
config that crashes the parser), or any boundary that fails *open* where it should
fail *closed*, please open a report. Include a minimal reproducer; for parser
crashes, the input bytes are enough.

## Scope reminders

- `unsafe` code count is currently **zero**; any future `unsafe` must be audited
  and documented (`docs/security-boundary.md`).
- No production-replacement claim is made. See `docs/deployment-boundary.md`.
