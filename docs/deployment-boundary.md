# Deployment boundary

`chrony-rs` advances along a strict ladder. A stage is only entered when the
previous stage's evidence exists. Skipping stages is forbidden.

| Stage | Description | Status |
|------:|-------------|--------|
| 0 | Archaeology only — source/design maps, no daemon claim | in progress |
| 1 | Config/control tools — `--check-config`, `chronyc`-compatible output where admitted | **current** — config diagnostics now **oracle-witnessed against chrony 4.5** (see `oracle.md`) |
| 2 | Packet engine — NTP encode/decode byte parity, hostile-input safe | **current** |
| 3 | Trace replay — deterministic chronyd trace replay (simulated clock/network) | **partial** — runner executes events deterministically; chrony selection/discipline policy not yet applied |
| 4 | Source-selection brain — accepted/rejected samples & source decisions match admitted traces | **partial** — reachability + selectability + falseticker intersection built & unit-tested (algorithmic, not yet oracle-witnessed or fed by real measurements) |
| 5 | Discipline model — slew/step/frequency decisions match admitted simulated traces | not started |
| 6 | Lab daemon — VM/container/netns only, no production claim | not started |
| 7 | Controlled real-clock discipline — isolated non-critical host, explicit consent, long-run receipts | not started |
| 8 | Production candidate — external review, packaging, security policy, soak | not started |
| 9 | Production replacement claim — only if evidence supports it | not started |

## Current admitted status

`chrony-rs` is at **Stage 1–2**. It:

- parses and validates chrony configs (`--check-config`),
- encodes/decodes NTP packets with byte-roundtrip and no-panic guarantees,
- renders `chronyc tracking` output offline,
- loads, validates, and **deterministically replays** traces through a simulated
  clock, emitting a reproducible decision-log hash (a regression pin). The
  replay does **not** yet apply chrony's source-selection or discipline policy —
  it processes events and observes state. See `negative-capabilities.md`.

## Hard boundaries (not yet crossed)

- **No host-clock mutation.** No code path steps or slews a real clock. There is
  `--lab-daemon` mode implemented, guarded and lab-only.
- **Live control socket implemented in lab mode.** `chronyc-rs` connects to the cmdmon server;
  it renders reports you supply. This is stated at the point of use (the binary
  fails closed with an explanation), not hidden.
- **No production-replacement claim.** None is made anywhere, and none will be
  until Stage 8+ evidence exists.

## What "current" means for a claim

A claim is only as strong as its stage. "chrony-rs matches `chronyc tracking`
layout" is a Stage-1 *output-layout* claim backed by a byte court; it is **not**
a claim that chrony-rs can talk to your daemon or discipline your clock. Read
every claim against this table.
