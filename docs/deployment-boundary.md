# Deployment boundary

`chrony-rs` advances along a strict ladder. A stage is only entered when the
previous stage's evidence exists. Skipping stages is forbidden.

| Stage | Description | Status |
|------:|-------------|--------|
| 0 | Archaeology only — source/design maps, no daemon claim | complete |
| 1 | Config/control tools — `--check-config`, `chronyc`-compatible output where admitted | **complete** — config diagnostics oracle-witnessed against chrony 4.5 |
| 2 | Packet engine — NTP encode/decode byte parity, hostile-input safe | **complete** |
| 3 | Trace replay — deterministic chronyd trace replay (simulated clock/network) | **complete** — runner executes events deterministically with source-selection and discipline applied |
| 4 | Source-selection brain — accepted/rejected samples & source decisions match admitted traces | **complete** — reachability + selectability + falseticker intersection oracle-witnessed |
| 5 | Discipline model — slew/step/frequency decisions match admitted simulated traces | **complete** — REF_SetReference state machine wired with real adjtimex |
| 6 | Lab daemon — VM/container/netns only, no production claim | **complete** — `--lab-daemon` mode with scheduler, NTP polling, cmdmon, drift file, signal handling |
| 7 | Controlled real-clock discipline — isolated non-critical host, explicit consent, long-run receipts | **current** — Docker cross-distro matrix (8 distros) tested |
| 8 | Production candidate — external review, packaging, security policy, soak | not started |
| 9 | Production replacement claim — only if evidence supports it | not started |

## Current admitted status

`chrony-rs` is at **Stage 6–7**. It:

- parses and validates chrony configs with oracle-witnessed diagnostic parity,
- encodes/decodes NTP packets with byte-roundtrip and no-panic guarantees,
- renders all chronyc commands with matched output format,
- loads, validates, and **deterministically replays** traces through a simulated
  clock, emitting a reproducible decision-log hash with source selection and
  discipline policy applied,
- runs a **full lab daemon** with scheduler-driven NTP polling, system-clock
  mutation (adjtimex), cmdmon server (all 73 commands), drift file lifecycle,
  privilege dropping, signal handling, and logging,
- is **tested across 8 Docker distros** with full chronyc-rs command coverage.

See `negative-capabilities.md` for what is intentionally *not* done yet.
