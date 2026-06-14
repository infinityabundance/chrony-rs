# Compatibility & court matrix

The single source of truth for what `chrony-rs` claims, and the evidence behind
each claim. A behavior is "admitted" only if it appears here with a court and a
reproducible test or receipt.

- **Target oracle:** chrony 4.6 (`TARGET_CHRONY_VERSION`).
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
| CHRONYC.1 | `chronyc tracking` label-aligned layout, byte-stable | `report.rs` + `chronyc-rs/tests/cli.rs` + receipt |
| (trace) | `chrony-rs-trace-v1` parse + monotonic-order + schema validation | `trace.rs` tests |
| (replay) | deterministic event processing: same trace ⇒ same decision-log hash; reject/decode of packets via the packet court; pinned-hash regression check | `replay.rs` tests + `chronyd-rs/tests/cli.rs` + receipt |
| (hash) | SHA-256 receipts match FIPS `""`/`"abc"`/multi-block vectors | `hash.rs` tests |
| (clock) | simulated clock: wall = mono + step offset; monotonic non-decreasing; no host mutation | `clock.rs` tests |

## Oracle status

No differential receipt against real `chronyd` exists yet. All current courts are
*internal* parity (against fixtures and reconstructed expectations). Promoting any
court to "oracle-witnessed" requires a captured `chronyd` artifact and a recorded
comparison under `reports/oracle/`. Until then, claims are scoped to the declared
fixtures, and numeric/diagnostic *wording* is marked normalized where noted.

## Explicitly not admitted

See `negative-capabilities.md`. In particular: no clock discipline, no source
selection/filtering, no live control socket, no NTS, no extension-field parsing,
no OS clock adapters.
