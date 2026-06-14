# chrony-rs receipts (v0.1.0)

Reproducible evidence for admitted courts. Regenerate with `tools/regen-receipts.sh`
and confirm the hashes below are unchanged. A diff here is a real parity/behavior
regression, not noise.

| Court | Artifact | SHA-256 |
|-------|----------|---------|
| CHRONYC.1 (tracking layout) | reports/chronyc/tracking.sample.out | 5e67586c1102ca7bb3893f27a133d8741a57c85a42825f8d09d5bcd6c848874c |
| CHRONY.CONFIG.3/.8 (check-config OK) | reports/config/check-config.minimal.out | 2628b351c1abc820e3227d6688cdb9c00a33315d925d3acc05f46ace1ba08caf |
| CHRONY.TRACE (replay determinism) | reports/trace-replay/sample-trace.out | e14078a535f8f439f93aed180c7385c90d30ad50a7e31cf0ea1163c79571e400 |

## Test suite

`cargo test` — 6 passing test binaries, 0 failures, recorded 2026-06-14T16:47:06Z.
`unsafe` count in crates/*/src: 0.

These receipts cover output byte-parity *layout* and *deterministic replay
self-consistency*. Differential comparison against real chronyd output (byte
parity against the oracle) is tracked in docs/compatibility.md and is not yet
claimed.
