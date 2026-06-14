# Compatibility & court matrix

The single source of truth for what `chrony-rs` claims, and the evidence behind
each claim. A behavior is "admitted" only if it appears here with a court and a
reproducible test or receipt.

- **Target oracle:** chrony 4.5 (`TARGET_CHRONY_VERSION`) — the version we can
  actually run and witness here. See `oracle.md` and `version-lineage.md`.
- **Trace schema:** `chrony-rs-trace-v1`.
- **Evidence:** unit/CLI tests in-tree; byte receipts under `reports/`.

> Claim language is bounded. "Admitted under court X" means: matches the declared
> behavior in the test/receipt for X, under the stated version and inputs. It does
> **not** imply parity with real `chronyd` output until a differential oracle
> receipt exists (none yet — see "Oracle status" below).

## Admitted courts (v0.1.0)

| Court | What it asserts | Evidence |
|-------|-----------------|----------|
| CHRONY.PACKET.* (subset) | 48-byte header decode→encode is byte-identical; tail preserved; too-short input rejected without panic; kiss-o-death detected | `ntp/packet.rs` tests |
| (timestamp) | NTP timestamp/short fixed-point bit-exact roundtrip | `ntp/timestamp.rs` tests |
| CHRONY.CONFIG.2/.3/.7/.8/.12 (subset) | comment/blank handling; server/pool/peer; makestep; driftfile; unknown-directive error | `config/*` tests |
| CHRONY.CONFIG (exit codes) | `--check-config` exits 0 clean / 1 on config error / 2 on usage-IO error | `chronyd-rs/tests/cli.rs` |
| CHRONY.CONFIG.14 (**oracle-witnessed, chrony 4.5**) | accept/reject agreement (7/7) + exact diagnostic phrasing for 5 error classes | `tools/oracle/capture-config.sh` + `reports/oracle/config/` + `config/parser.rs` test |
| CHRONYC.1 | `chronyc tracking` label-aligned layout, byte-stable | `report.rs` + `chronyc-rs/tests/cli.rs` + receipt |
| (trace) | `chrony-rs-trace-v1` parse + monotonic-order + schema validation | `trace.rs` tests |
| (replay) | deterministic event processing: same trace ⇒ same decision-log hash; reject/decode of packets via the packet court; pinned-hash regression check | `replay.rs` tests + `chronyd-rs/tests/cli.rs` + receipt |
| (hash) | SHA-256 receipts match FIPS `""`/`"abc"`/multi-block vectors | `hash.rs` tests |
| (clock) | simulated clock: wall = mono + step offset; monotonic non-decreasing; no host mutation | `clock.rs` tests |
| CHRONY.SOURCE.2 | 8-bit reachability register: shift/mask, reachable⇔≠0, decay after 8 misses, octal display | `sources/reachability.rs` tests |
| CHRONY.SOURCE.6/.7 | selectability gate: offline/unreachable/no-sample/stratum-0/stratum-16 excluded before interval math | `sources/source.rs` + `selection.rs` tests |
| CHRONY.FILTER.8 (subset, **algorithmic**) | falseticker rejection by majority-clique interval intersection; min-root-distance stand-in pick | `sources/selection.rs` tests |
| (measurement) | offset/delay from four-timestamp exchange (RFC 5905 §8); era-safe wrapping differences; negative-offset & rollover vectors | `ntp/measurements.rs` tests |
| (pipeline, **algorithmic**) | computed offsets → sample summaries → falseticker selection, end to end | `tests/pipeline.rs` |

## Oracle status

**First oracle-witnessed court landed:** config diagnostics against real chrony
4.5. `tools/oracle/capture-config.sh` records 0 accept/reject disagreements over 7
fixtures, and chrony-rs reproduces chrony 4.5's exact error phrasing for 5 error
classes (receipts under `reports/oracle/config/`; see `oracle.md`).

Other courts remain *internal/algorithmic* parity (fixtures and reconstructed
expectations), not yet oracle-witnessed:

- `chronyc tracking` layout — live capture was **environmental** (a resident
  `chronyd` would not run in this sandbox); validated against a reconstructed
  fixture only. See `oracle.md`.
- packet/measurement — RFC-anchored, not yet diffed against chrony captures.
- source selection — algorithmic reconstruction, no oracle capture yet.

## Explicitly not admitted

See `negative-capabilities.md`. In particular: no clock discipline, no source
selection/filtering, no live control socket, no NTS, no extension-field parsing,
no OS clock adapters.
