# Source-selection atlas

Behavior court for how chrony decides which sources are usable and which one to
follow. Implemented in `chrony-rs-core/src/sources/`.

## Confidence levels (this matters — selection is policy, not plumbing)

| Piece | Module | Confidence |
|-------|--------|------------|
| Reachability shift register | `reachability.rs` | **high** — exactly specified chrony behavior, reconstructed precisely |
| Source selectability gate | `source.rs` | high — offline/unreachable/no-sample/bad-stratum exclusion |
| Root distance `disp + delay/2` | `source.rs` | high — chrony's synchronisation-distance definition |
| Falseticker intersection | `selection.rs` | **medium** — core idea reproduced; not chrony's full selector |
| Cluster/combine, `f`-loop, hysteresis | — | **not implemented** |

## Reachability (`CHRONY.SOURCE.2`)

An 8-bit shift register (`SOURCE_REACH_BITS = 8`). Each poll shifts left; success
sets the low bit; the value is masked to 8 bits. Reachable ⇔ register ≠ 0. A
reachable source decays to unreachable only after **8 consecutive misses**. The
operator-facing value is octal (`377` = all set); reachability % is the popcount.

## Selectability (`CHRONY.SOURCE.6/.7`)

A source participates in selection only if it is online, reachable, has a sample,
and advertises a usable stratum (not 0 = kiss/unspec, not 16 = unsynchronised).
Excluded sources are partitioned out **before** the interval math, so a stratum-16
server cannot drag the intersection.

## Falseticker intersection (`CHRONY.FILTER.8`)

Each selectable source becomes a closed interval `[offset ± root_distance]`. A
maximum-overlap sweep finds the largest mutually-overlapping set — the *majority
clique* of truechimers. Sources outside it are falsetickers. A strict majority
(clique × 2 > selectable count) is required; without one, nothing is selected and
no source is blamed.

### What is deliberately NOT reproduced

- chrony's incremental `f`-falseticker tolerance loop with midpoint refinement
  (RFC 5905 §11.2.1 style),
- the clustering/combining stage (jitter-weighted trimming),
- `prefer`/`trust` bias and reselection hysteresis (`reselectdist`).

The `selected` source here is "smallest root distance among truechimers" — a
documented stand-in for chrony's cluster pick, **not** chrony's output.

## Oracle status

This is an **algorithmic court**, not oracle-witnessed. Promoting it requires a
captured `chronyd` selection scenario (`reports/oracle/`) and a recorded match of
truechimer/falseticker classification and the final pick. Until then, claims are
scoped to the deterministic fixtures in `selection.rs`.

## Not yet wired into replay

Selection consumes per-source **offsets**, which come from the measurement stage
(computing offset/delay from the four NTP timestamps). That stage is not built
yet, so the replay runner does not feed real intervals into the selector. Wiring
them together is the next campaign; doing it before measurement exists would mean
inventing offsets, which is forbidden.
