# Source archaeology

Before porting behavior, map where it lives in upstream chrony. This document is
the navigable index from chrony semantics → C source location → `chrony-rs`
module. It is a *map under construction*: entries marked (planned) are targets for
the excavation campaign, not yet completed findings.

> Method note: locations reference chrony's C sources by file/role rather than by
> line number, because line numbers drift across versions. Version-anchored
> findings belong in `version-lineage.md`.

## Archaeology index (`CHRONY.ARCHAEOLOGY.*`)

| ID | Map | Status |
|----|-----|--------|
| 1 | source file map | partial (below) |
| 2 | call graph | planned |
| 3 | global state atlas | planned |
| 4 | event loop map | planned |
| 5 | source-selection flow map | planned |
| 6 | sample-filter flow map | planned |
| 7 | discipline-control flow map | planned |
| 8 | control protocol map | planned |
| 9 | OS adapter map | planned |
| 10 | diagnostic/log origin map | planned |
| 11 | version lineage map | planned |
| 12 | vendor/distro ecology map | planned |

## Behavior → upstream role (partial)

| Behavior | chrony C role | chrony-rs location |
|----------|---------------|--------------------|
| config parsing | `conf.c` (directive dispatch table) | `config/parser.rs` |
| config tokenizing | `getword`-style splitting, `cmdparse.c` | `config/lexer.rs` |
| NTP packet decode/encode | `ntp_io.c` / `ntp_core.c` packet structs | `ntp/packet.rs` |
| NTP timestamps | `ntp.h` `NTP_int64`, `ntp_core.c` | `ntp/timestamp.rs` |
| offset/delay measurement | `ntp_core.c` (`NCR_ProcessResponse`) | `ntp/measurements.rs` (RFC 5905 §8 algebra) |
| `tracking` report | `client.c` (`process_cmd_tracking`) / `reports.h` | `report.rs` |
| source reachability | `sources.c` (`SRC_UpdateReachability`) | `sources/reachability.rs` (implemented) |
| source selectability | `sources.c` (selectability checks) | `sources/source.rs` (implemented) |
| sample filtering | `sourcestats.c` regression | (planned) `filter/` |
| source selection | `sources.c` (`SRC_SelectSource`) | `sources/selection.rs` (partial: falseticker intersection) |
| clock discipline | `local.c` / `reference.c` | (planned) `discipline/` |
| drift state | `reference.c` (drift file load/save) | (planned) `state/drift_file.rs` |
| control protocol | `cmdmon.c` / `candm.h` | (planned) `control/` |
| OS clock mutation | `sys_linux.c` / `sys_*` | (planned) `os/` |

## How to extend this map

1. Identify the behavior and the court that will admit it.
2. Locate the upstream C role (Doxygen/source index output goes under
   `research/doxygen/` when generated).
3. Record the finding here with the chrony-rs destination module.
4. Do **not** port until the relevant flow is mapped — "first build the map."
