# chrony-rs receipts (v0.1.0)

Reproducible evidence for admitted courts. Regenerate with `tools/regen-receipts.sh`
(internal) and `tools/oracle/capture-config.sh` (oracle differential), then confirm
the hashes/results below are unchanged. A diff is a real regression, not noise.

## Internal parity receipts

| Court | Artifact | SHA-256 |
|-------|----------|---------|
| CHRONYC.1 (tracking layout) | reports/chronyc/tracking.sample.out | 5e67586c1102ca7bb3893f27a133d8741a57c85a42825f8d09d5bcd6c848874c |
| CHRONY.CONFIG.3/.8 (check-config OK) | reports/config/check-config.minimal.out | 2628b351c1abc820e3227d6688cdb9c00a33315d925d3acc05f46ace1ba08caf |
| CHRONY.TRACE (replay determinism) | reports/trace-replay/sample-trace.out | 835c5a577d0ef1538292f3cb9189d460dfe1a6a7824e5c2a2fa2d8bd79319176 |

## Oracle-witnessed receipts (chrony 4.5)

Oracle: `chronyd (chrony) version 4.5 (+CMDMON +NTP +REFCLOCK +RTC +PRIVDROP +SCFILTER +SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG)`

Differential `chronyd -p` vs `chronyd-rs --check-config` over 14 config fixtures:
**0 accept/reject disagreements**, exact diagnostic phrasing for 5 error classes; 93/93 directives recognized.
Per-fixture receipts and table: `reports/oracle/config/` (SUMMARY.md + *.receipt).

## Test suite

`cargo test` — 7 passing test binaries, 0 failures, recorded 2026-06-14T17:12:54Z.
`unsafe` count in crates/*/src: 0.

Internal receipts cover output-layout byte-parity and deterministic replay
self-consistency. The config court is now oracle-witnessed against chrony 4.5;
other courts remain internal/algorithmic (see docs/compatibility.md).
