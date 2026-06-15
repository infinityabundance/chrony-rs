# chrony-rs

`chrony-rs` is a **forensic Rust reconstruction of chrony's time-discipline
behavior**. It is developed by differential comparison against `chronyd`,
deterministic trace replay, packet-level byte receipts, and explicit
deployment-boundary documentation.

This is **not** a clean-room "inspired by chrony" rewrite, not a toy NTP daemon,
and not a production replacement. The C chrony implementation remains the primary
behavioral oracle; independent NTP/protocol witnesses are used only to classify
where chrony policy differs from generic protocol truth.

## What exists today (v0.1.0, Stage 0→2 complete; Stage 3–4 partial; first oracle court landed)

| Surface | Status |
|---------|--------|
| MD5 (RFC 1321) for NTP symmetric-key auth | **complete port of `md5.c`** (all 4 functions); byte-exact vs RFC 1321 §A.5 vectors |
| Symmetric key store + NTP MAC auth | **complete port of `keys.c`** (all 17 functions, internal-MD5 build): key-file parse, sorted store + binary search, MAC generate/verify; vs the REAL compiled keys.c (per-id MAC vectors) + an independent `MD5(key‖msg)` check |
| NTP/cmd access control (allow/deny subnet trie) | **complete port of `addrfilt.c`** (all 16 functions); decisions **live-witnessed vs `chronyc accheck`** on chrony 4.5 |
| Robust regression | **complete port of `regress.c`** (all 11 functions): weighted LS, runs-test & median-based robust fits, 2-var regression; vs the REAL compiled regress.c (80 differential vectors) + an independent reference |
| Client access log + response rate limiter | **complete port of `clientlog.c`** (all 35 functions): per-client hash table, per-service token-bucket limiter w/ probabilistic leak, log2 rate estimate, interleaved-mode RX→TX timestamp map; vs the REAL compiled clientlog.c (5-scenario differential fixture) + an independent token-bucket invariant |
| Streaming quantile estimator | **complete port of `quantiles.c`** (all 8 functions); structural (convergence-tested; inherently non-deterministic so not byte-witnessed) |
| NTP packet decode/encode (48-byte header) | byte-roundtrip courts `CHRONY.PACKET.1–.13` (subset admitted) |
| NTP timestamp / short fixed-point types | bit-exact roundtrip |
| chrony config parser + `--check-config` | `CHRONY.CONFIG` subset; **oracle-witnessed against chrony 4.5** — 8/8 accept/reject agreement (incl. Ubuntu default) + exact phrasing for 5 error classes; 82-directive set oracle-anchored |
| `chronyc tracking` / `sources` output layout | byte-stable courts `CHRONYC.1`/`.2`; `sources` header+legend **live-witnessed vs chrony 4.5**, rows byte-derived from `client.c` (offline render) |
| Deterministic trace schema (`chrony-rs-trace-v1`) | parse + structural validation |
| `chronyd-rs --replay` | **deterministic replay** through a simulated clock; reproducible decision-log hash + pinned-hash regression check (chrony selection/discipline policy not yet applied) |
| NTP offset/delay measurement | RFC 5905 §8 algebra, era-safe differences (`ntp::Measurement`) |
| Source reachability + selection | 8-bit reach register (exact); selectability gate; falseticker interval intersection driven by computed offsets (`sources/`, `tests/pipeline.rs`) — algorithmic, not yet oracle-witnessed |
| SHA-256 receipts | dependency-free, FIPS-vectored (`hash.rs`) |
| Generic software-slew clock discipline | **complete port of `sys_generic.c`** (all 14 functions): offset→frequency slew model (bounded rate/duration, `offset_convert`, dispersion); vs the REAL compiled sys_generic.c + an independent slew-drain check |
| `adjtimex()` clock driver | **complete port of `sys_timex.c`** (all 10 functions, Linux build): ppm⇄kernel-freq scaling, sync-status/leap/TAI bookkeeping over the `struct timex` ABI (syscall injected); vs the REAL compiled sys_timex.c (every submitted `timex` captured) + an independent scaling check |
| Simulated clock | side-effect-free time base, no host mutation (`clock.rs`) |
| Source archaeology + ecology docs | scaffolded under `docs/` |

Run:

```sh
cargo build
cargo test                                    # deterministic; count shown in output
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
xtask              doc generation + freshness gating (cargo xtask gen|check)
```

Host mutation (clock, sockets, privileges) is kept behind narrow trait boundaries
so the brain is testable without the real system clock. See
[`docs/architecture.md`](docs/architecture.md).

## Generated docs & freshness gate

Machine-derivable facts (target chrony version, the recognized-directive set,
source-option tables, `unsafe` count, oracle fixtures) are generated from the code
into [`docs/generated/`](docs/generated/) by `cargo xtask gen`. This includes the
**[port-parity matrix](docs/generated/port-parity.md)** — a 1:1 completeness catalog
of every chrony 4.5 `.c` file (doxygen inventory) against its chrony-rs counterpart
(`syn` AST inventory), plus a
**[per-function gap view](docs/generated/port-parity-functions.md)** giving each
file's ported-vs-gap functions and percentage; method in
[`docs/port-parity.md`](docs/port-parity.md). The
**[negative-capabilities ledger](docs/negative-capabilities.md)** is generated too —
its "implemented modules" list is derived from the parity matrix, so it can never
claim a ported module is absent.

A pre-commit hook runs `cargo xtask check`, which rejects any commit where (1) a
generated doc is stale, or (2) a curated prose doc has drifted from a machine fact
it restates (the chrony version, directive count, source-inventory totals, and
`unsafe` count are each pinned to their canonical doc). Nothing documented —
generated *or* prose — can silently drift from the code. Activate the hook with:

```sh
git config core.hooksPath .githooks
```

## Source archaeology

The chrony 4.5 C source is the structural oracle. Its directive dispatch
(`conf.c`) and source-option tables (`cmdparse.c`) were extracted by Doxygen-style
indexing and diffed against chrony-rs — see [`research/`](research/) and
[`docs/source-archaeology.md`](docs/source-archaeology.md). That diff plus the
live `chronyd -p` oracle is how the config surface reached 1:1: 93/93 directives
recognized, exact diagnostics, and source-option validation matching chrony.

## Doctrine

> Byte parity, behavior parity, operational-knowledge parity.

Every admitted behavior must be backed by a court with reproducible evidence
(`reports/`). Code ports should not be transliterations; they should be
archaeological restorations with executable evidence. The verbose source comments
are part of the deliverable: a future engineer should understand chrony *better*
from this reconstruction than from the C alone.

## License

GPL-2.0-only, matching chrony's licensing posture. See [`LICENSE`](LICENSE).
