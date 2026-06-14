# Source archaeology

Before porting behavior, map where it lives in upstream chrony. This document is
the navigable index from chrony semantics → C source location → `chrony-rs`
module. It is a *map under construction*: entries marked (planned) are targets for
the excavation campaign, not yet completed findings.

> Method note: locations reference chrony's C sources by file/role rather than by
> line number, because line numbers drift across versions. Version-anchored
> findings belong in `version-lineage.md`.

## Doxygen method

The chrony 4.5 source is indexed with Doxygen (~310 entities; `conf.c` alone has
~135 functions). The index is regenerable, not vendored — see
`research/doxygen/README.md`. Diffing the C surface against chrony-rs is how the
recognition/option tables were made exact:

- The **config directive set** was extracted from `conf.c`'s `strcasecmp(command,
  …)` dispatch (93 entries) and diffed against `KNOWN_DIRECTIVES`. The diff found
  **11 directives chrony-rs was missing**; an earlier `chronyd -p` oracle sweep had
  found **5 fabricated** entries. Net: a measured 93-entry set, 1:1 with chrony 4.5.
- The **source-option tables** (`server`/`pool`/`peer`) came from
  `cmdparse.c::CPS_ParseNTPSourceAdd` and `CPS_GetSelectOption`.
- The **comment characters** (`# % ! ;`, line-start only) came from `conf.c`.

Extracted tables and provenance: `research/source-archaeology/`.

The same doxygen index, run over the **whole** C tree, yields the per-file function
inventory (70 `.c` files, 1373 functions) committed at
`research/doxygen/chrony-4.5-c-inventory.tsv`. That inventory is the denominator for
the **port-parity matrix** (`docs/port-parity.md` →
`docs/generated/port-parity.md`), which catalogs every C translation unit against
its chrony-rs counterpart. The Rust side of that matrix is anchored with the `syn`
AST, not doxygen (whose C++ frontend misparses Rust).

## Archaeology index (`CHRONY.ARCHAEOLOGY.*`)

| ID | Map | Status |
|----|-----|--------|
| 1 | source file map | partial (below) + Doxygen index (`research/doxygen/`) |
| 2 | call graph | Doxygen XML available; map planned |
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
| config parsing | `conf.c` (`CNF_ParseLine` dispatch, 93 directives) | `config/parser.rs` |
| config tokenizing | `conf.c` line handling; comment chars `# % ! ;` | `config/lexer.rs` |
| source options | `cmdparse.c::CPS_ParseNTPSourceAdd`, `CPS_GetSelectOption` | `config/parser.rs::parse_source` |
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
