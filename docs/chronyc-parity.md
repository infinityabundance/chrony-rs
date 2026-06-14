# chronyc parity

Output-parity court for the `chronyc` control tool. Implemented in
`chrony-rs-core/src/report.rs` and exposed via `chronyc-rs`.

## What is admitted

- **`tracking` layout** (`CHRONYC.1`). The label-aligned block: a 16-character
  left-justified label, then `": "`, then the value. Byte-stable and tested two
  ways — a golden-block comparison and a structural assertion that every label
  aligns to column 16. A receipt is stored at
  `reports/chronyc/tracking.sample.out`.

  **Oracle status: reconstructed, not yet live-witnessed.** Capturing real
  `chronyc tracking` output needs a resident `chronyd`, which would not run in
  this sandbox — classified **environmental** (see `oracle.md`). The layout court
  is therefore validated against a reconstructed fixture, pending a live 4.5
  capture.

## What is normalized (not yet oracle-exact)

The *numeric formatting and phrasing* of `tracking` values is reconstructed from
observed chrony output but only claimed exact once witnessed against real
`chronyc`. Specifically pending witness:

- sign conventions (`+` on `Last offset`/`Residual freq`),
- `"fast"/"slow of NTP time"` wording and the zero-case (chrony's `> 0` test
  renders zero as "slow"; we match that),
- ppm precision (`%.3f`) and seconds precision (`%.9f`),
- `Leap status` strings (note British "Not synchronised").

## What is deferred (negative capability)

- **Live control socket.** `chronyc-rs` cannot connect to a running daemon. A
  bare `chronyc-rs tracking` (and `sources`/`sourcestats`/`activity`/`ntpdata`)
  fails closed with exit code 3 and an explanation. Only
  `chronyc-rs render-tracking <fixture.json>` works today.
- **Other reports.** `sources`, `sourcestats`, `clients`, `serverstats`, etc.
  are not yet rendered (`CHRONYC.2`–`CHRONYC.14`).

## Court status

| ID | Description | Status |
|----|-------------|--------|
| 1 | tracking | admitted (layout); numeric wording normalized |
| 2 | sources | not started |
| 3 | sourcestats | not started |
| 4–9 | activity/ntpdata/clients/serverstats/makestep/offline-online | not started |
| 10 | command errors | partial (deferred-capability error path tested) |
| 11 | output formatting | partial (tracking only) |
| 12 | exit codes | partial (render OK = 0, bad fixture = 1, IO = 2, deferred = 3) |
| 13 | Unix socket protocol | deferred |
| 14 | UDP/control protocol | deferred |
