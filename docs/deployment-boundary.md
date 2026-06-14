# Deployment boundary

`chrony-rs` advances along a strict ladder. A stage is only entered when the
previous stage's evidence exists. Skipping stages is forbidden.

| Stage | Description | Status |
|------:|-------------|--------|
| 0 | Archaeology only — source/design maps, no daemon claim | in progress |
| 1 | Config/control tools — `--check-config`, `chronyc`-compatible output where admitted | **current** |
| 2 | Packet engine — NTP encode/decode byte parity, hostile-input safe | **current** |
| 3 | Trace replay — deterministic chronyd trace replay (simulated clock/network) | schema only |
| 4 | Source-selection brain — accepted/rejected samples & source decisions match admitted traces | not started |
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
- loads and structurally validates replay traces.

## Hard boundaries (not yet crossed)

- **No host-clock mutation.** No code path steps or slews a real clock. There is
  no `--lab-daemon` mode yet, and when one lands it will be guarded and lab-only.
- **No live control socket.** `chronyc-rs` cannot connect to a running daemon;
  it renders reports you supply. This is stated at the point of use (the binary
  fails closed with an explanation), not hidden.
- **No production-replacement claim.** None is made anywhere, and none will be
  until Stage 8+ evidence exists.

## What "current" means for a claim

A claim is only as strong as its stage. "chrony-rs matches `chronyc tracking`
layout" is a Stage-1 *output-layout* claim backed by a byte court; it is **not**
a claim that chrony-rs can talk to your daemon or discipline your clock. Read
every claim against this table.
