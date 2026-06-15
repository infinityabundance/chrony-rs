# Live chronyc 4.5 oracle captures

Real output from `chronyc` **4.5** talking to a live `chronyd` **4.5** over its
Unix command socket. These exist because the daemon *does* run in this lab
environment — which corrects the earlier hedge in `docs/chronyc-parity.md` that a
resident `chronyd` was unavailable ("classified environmental"). It is available;
these are the receipts.

## Provenance

- chrony version: `4.5` (both `chronyd` and `chronyc`; `chronyc --version` →
  `chronyc (chrony) version 4.5 (+READLINE +SECHASH +IPV6 -DEBUG)`).
- Daemon: launched in a throwaway lab config with **no clock control** (`chronyd
  -x`), `user root`, `cmdport 0`, a single `local stratum 10` reference, and a
  per-run `bindcmdaddress` Unix socket under a temp dir. No host clock was touched
  ("Disabled control of system clock" in the daemon log) — consistent with
  `docs/deployment-boundary.md`.
- Captured with `chronyc -h <socket> {tracking,sources,sources -v,sourcestats}`.

## Files

| File | Command | Use |
|------|---------|-----|
| `tracking.raw.out` | `chronyc tracking` | confirms the `report.rs` label block: 16-char left-justified label, `": "`, value — byte-for-byte |
| `sources.raw.out` | `chronyc sources` | header + `=`-rule for the (not-yet-ported) `sources` formatter (`client.c::print_report`) |
| `sources-v.raw.out` | `chronyc sources -v` | the verbose legend block (mode/state glyph key) |
| `sourcestats.raw.out` | `chronyc sourcestats` | header for the (not-yet-ported) `sourcestats` formatter |
| `sourcestats-v.raw.out` | `chronyc sourcestats -v` | verbose legend block for `sourcestats` |
| `accheck.raw.out` | `chronyc accheck <ip>` | allow/deny verdicts for a configured rule set — the live oracle for `addrfilt.rs` (`ADF_IsAllowed`) |
| `activity.raw.out` | `chronyc activity` | full activity output (incl. `200 OK`) — oracle for `ActivityReport` |
| `serverstats.raw.out` | `chronyc serverstats` | 17 server counters — label/alignment oracle for `ServerstatsReport` (values volatile) |

## Volatile fields (do not treat as byte-stable)

`tracking.raw.out` contains run-dependent values — `Ref time (UTC)` is a wall-clock
timestamp, and with a bare `local` reference the offsets/frequencies are all zero.
These captures pin the **layout and phrasing**, not specific numbers. A byte-stable
court still drives off a fixed fixture (`CHRONYC.1`); this is the oracle the fixture
is reconciled against, not a golden file itself.
