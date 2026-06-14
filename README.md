# chrony-rs

`chrony-rs` is a **forensic Rust reconstruction of chrony's time-discipline
behavior**. It is developed by differential comparison against `chronyd`,
deterministic trace replay, packet-level byte receipts, and explicit
deployment-boundary documentation.

This is **not** a clean-room "inspired by chrony" rewrite, not a toy NTP daemon,
and not a production replacement. The C chrony implementation remains the primary
behavioral oracle; independent NTP/protocol witnesses are used only to classify
where chrony policy differs from generic protocol truth.

## What exists today (v0.1.0, Stage 0→2 complete, Stage 3 partial)

| Surface | Status |
|---------|--------|
| NTP packet decode/encode (48-byte header) | byte-roundtrip courts `CHRONY.PACKET.1–.13` (subset admitted) |
| NTP timestamp / short fixed-point types | bit-exact roundtrip |
| chrony config parser + `--check-config` | `CHRONY.CONFIG` subset; recognizes all known directives, models a subset |
| `chronyc tracking` output layout | byte-stable layout court `CHRONYC.1` (offline render) |
| Deterministic trace schema (`chrony-rs-trace-v1`) | parse + structural validation |
| `chronyd-rs --replay` | **deterministic replay** through a simulated clock; reproducible decision-log hash + pinned-hash regression check (chrony selection/discipline policy not yet applied) |
| SHA-256 receipts | dependency-free, FIPS-vectored (`hash.rs`) |
| Simulated clock | side-effect-free time base, no host mutation (`clock.rs`) |
| Source archaeology + ecology docs | scaffolded under `docs/` |

Run:

```sh
cargo build
cargo test                                    # 48 tests, deterministic
chronyd-rs --check-config examples/minimal.conf
chronyd-rs --replay <trace.json>
chronyc-rs render-tracking <fixture.json>
```

## What is intentionally NOT claimed

`chrony-rs` does **not** discipline a real system clock, does not connect to a
running daemon over the control socket, and makes **no production-replacement
claim**. These are deliberate, documented boundaries — see
[`docs/deployment-boundary.md`](docs/deployment-boundary.md) and
[`docs/negative-capabilities.md`](docs/negative-capabilities.md). Host-clock
mutation is forbidden outside declared lab courts.

Production-replacement claims are bounded by the admitted courts in
[`docs/compatibility.md`](docs/compatibility.md). Where behavior is unknown,
environmental, or version-dependent, it is classified as such rather than
approximated.

## Architecture

A lean Cargo workspace:

```
crates/
  chrony-rs-core   deterministic time-discipline brain (no host clock, no sockets)
  chronyd-rs       daemon/replay binary (lab & offline modes only)
  chronyc-rs       control client & output-parity tool
```

Host mutation (clock, sockets, privileges) is kept behind narrow trait boundaries
so the brain is testable without the real system clock. See
[`docs/architecture.md`](docs/architecture.md).

## Doctrine

> Byte parity, behavior parity, operational-knowledge parity.

Every admitted behavior must be backed by a court with reproducible evidence
(`reports/`). Code ports should not be transliterations; they should be
archaeological restorations with executable evidence. The verbose source comments
are part of the deliverable: a future engineer should understand chrony *better*
from this reconstruction than from the C alone.

## License

GPL-2.0-only, matching chrony's licensing posture. See [`LICENSE`](LICENSE).
