# Security boundary

chrony is privileged, network-facing, clock-mutating infrastructure. This document
records the trust boundaries `chrony-rs` reasons about and the current posture at
each. Most are not yet *crossed* (no daemon, no clock, no sockets), but the
boundary is documented now so it is never crossed silently.

## Unsafe / FFI

- **`unsafe` count: 0.** No `unsafe` blocks exist in the workspace. This is
  recorded explicitly (per doctrine) so that the first addition is conspicuous and
  must arrive with an unsafe-boundary receipt (`CHRONY.SECURITY.1`).
- Verify with: `grep -rn "unsafe" crates/*/src` (expected: no matches).

## Untrusted inputs and current handling

| Input | Trust | Current handling |
|-------|-------|------------------|
| NTP packet bytes | untrusted | total decode, no panic; too-short rejected (`CHRONY.PACKET.8` / `CHRONY.SECURITY.2`) |
| config file | semi-trusted (operator) | fails closed on read error; typed diagnostics; no path following yet |
| replay trace JSON | semi-trusted | schema + monotonic-order validated before use |
| tracking fixture JSON | semi-trusted | parsed with typed errors; bad input → exit 1 |
| control commands | untrusted | **not yet accepted** (no live socket) |
| refclock/RTC devices | untrusted | **not yet accessed** |
| NTS key material | secret | **not yet handled** |

## Panic policy

Library code in `chrony-rs-core` does not panic on input: parsing and decoding
return `Result`. The few `expect(...)` calls in the packet decoder are guarded by
a prior length check and carry messages explaining why they cannot fire; they are
invariants, not input validation.

## Process boundaries (planned, not implemented)

Raw/UDP sockets, privilege drop, Linux capabilities, chroot, control-socket
permissions, temp/state file handling, and resource-exhaustion limits are all
**deferred** to the lab-daemon stage and tracked in `privilege-boundary.md` (to be
written when Stage 6 work begins). No production-mode default exists; the daemon
will refuse unsafe production mode unless explicitly enabled
(`CHRONY.SECURITY.7`).

## Reporting

See `SECURITY.md` at the repository root.
