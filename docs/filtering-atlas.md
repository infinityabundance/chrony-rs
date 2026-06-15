# Filtering atlas

Court for sample filtering and the falseticker/clustering decisions that sit
between raw measurements and source selection. Most of this campaign is **not yet
implemented**; this document records the plan and the one piece that exists.

## Implemented

| ID | Description | Where |
|----|-------------|-------|
| (measurement) | offset/delay from the four-timestamp exchange (RFC 5905 §8), era-safe differences | `ntp/measurements.rs` |
| CHRONY.FILTER.4 (partial) | root distance `disp + delay/2`; per-sample summary derived from a measurement | `sources/source.rs` + `ntp/measurements.rs` |
| CHRONY.FILTER.8 (subset) | falseticker scenario — a clear outlier among agreeing sources is rejected by interval intersection, driven by **computed** offsets | `sources/selection.rs` + `tests/pipeline.rs` |

## Not yet implemented

| ID | Description | Blocking dependency |
|----|-------------|---------------------|
| CHRONY.FILTER.1 | first sample | sample history container |
| CHRONY.FILTER.2 | jitter | sample history + regression |
| CHRONY.FILTER.3 | delay | sample history (per-sample delay now available) |
| CHRONY.FILTER.5 | sample aging | dispersion growth over time |
| CHRONY.FILTER.6 | sample rejection | sample history + bounds |
| CHRONY.FILTER.7 | noisy source | regression estimator |
| CHRONY.FILTER.9 | source clustering | chrony cluster/combine stage |
| CHRONY.FILTER.10 | source combining | chrony combine stage |
| CHRONY.FILTER.11 | preferred source | `prefer` bias in selection |
| CHRONY.FILTER.12 | trust/require | admission TBD |
| CHRONY.FILTER.13 | adversarial source | hostile-input campaign |

## Dependency status

Measurement — turning the four NTP timestamps into an offset and round-trip delay
— is **now implemented** (`ntp/measurements.rs`), and `tests/pipeline.rs` drives
selection with computed offsets end to end. What remains before the daemon can do
this on live traffic is *exchange tracking*: recording T1 (our transmit) and T4
(our receive) per poll, which is daemon state not yet built. So the pieces exist
and compose, but are not yet wired into the live/replay loop.

## Oracle status

The implemented falseticker court is **algorithmic**, validated against
constructed fixtures, not a captured `chronyd` run. See `compatibility.md`.
