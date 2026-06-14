# chronyc parity

Output-parity court for the `chronyc` control tool. Implemented in
`chrony-rs-core/src/report.rs` and exposed via `chronyc-rs`.

## What is admitted

- **`tracking` layout** (`CHRONYC.1`). The label-aligned block: a 16-character
  left-justified label, then `": "`, then the value. Byte-stable and tested two
  ways — a golden-block comparison and a structural assertion that every label
  aligns to column 16. A receipt is stored at
  `reports/chronyc/tracking.sample.out`.

  **Oracle status: layout live-witnessed against chrony 4.5.** A resident
  `chronyd` 4.5 *does* run in the lab environment, so the earlier "environmental,
  cannot witness" hedge no longer holds. Real `chronyc tracking` output is captured
  at `reports/oracle/chronyc-live/tracking.raw.out` and confirms the `report.rs`
  label block byte-for-byte (16-char label, `": "`, value). The byte-stable court
  still drives off a fixed fixture (`CHRONYC.1`) because live numbers/timestamps are
  volatile; the live capture is what that fixture's *layout* is reconciled against.

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
| 1 | tracking | admitted (layout); **layout live-witnessed vs 4.5**; numeric wording normalized |
| 2 | sources | not started (header oracle captured: `reports/oracle/chronyc-live/sources.raw.out`) |
| 3 | sourcestats | not started (header oracle captured: `reports/oracle/chronyc-live/sourcestats.raw.out`) |
| 4–9 | activity/ntpdata/clients/serverstats/makestep/offline-online | not started |
| 10 | command errors | partial (deferred-capability error path tested) |
| 11 | output formatting | partial (tracking only) |
| 12 | exit codes | partial (render OK = 0, bad fixture = 1, IO = 2, deferred = 3) |
| 13 | Unix socket protocol | deferred |
| 14 | UDP/control protocol | deferred |
