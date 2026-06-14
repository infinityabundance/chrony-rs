# Filtering atlas

Court for sample filtering and the falseticker/clustering decisions that sit
between raw measurements and source selection. Most of this campaign is **not yet
implemented**; this document records the plan and the one piece that exists.

## Implemented

| ID | Description | Where |
|----|-------------|-------|
| CHRONY.FILTER.8 (subset) | falseticker scenario — a clear outlier among agreeing sources is rejected by interval intersection | `sources/selection.rs` |

## Not yet implemented

| ID | Description | Blocking dependency |
|----|-------------|---------------------|
| CHRONY.FILTER.1 | first sample | measurement stage (offset/delay from timestamps) |
| CHRONY.FILTER.2 | jitter | sample history + regression |
| CHRONY.FILTER.3 | delay | measurement stage |
| CHRONY.FILTER.4 | root distance | partially present (`SampleSummary::root_distance`) |
| CHRONY.FILTER.5 | sample aging | dispersion growth over time |
| CHRONY.FILTER.6 | sample rejection | measurement stage |
| CHRONY.FILTER.7 | noisy source | regression estimator |
| CHRONY.FILTER.9 | source clustering | chrony cluster/combine stage |
| CHRONY.FILTER.10 | source combining | chrony combine stage |
| CHRONY.FILTER.11 | preferred source | `prefer` bias in selection |
| CHRONY.FILTER.12 | trust/require | admission TBD |
| CHRONY.FILTER.13 | adversarial source | hostile-input campaign |

## The dependency that gates the rest

Almost everything here needs **measurement**: turning the four NTP timestamps
(origin/receive/transmit + local receive) into an offset and round-trip delay.
That computation is the next campaign. Selection (`source-selection-atlas.md`) is
built and unit-tested but cannot be fed real intervals until measurement lands —
and we do not fabricate offsets to make a court look further along than it is.

## Oracle status

The implemented falseticker court is **algorithmic**, validated against
constructed fixtures, not a captured `chronyd` run. See `compatibility.md`.
