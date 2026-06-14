# chrony-rs documentation archive

The operational-knowledge half of the project. The crate stays lean; this archive
preserves the reasoning, courts, and ecology maps.

## Present

| Doc | Purpose |
|-----|---------|
| [architecture.md](architecture.md) | workspace layout, trait boundaries, design rationale |
| [compatibility.md](compatibility.md) | the court matrix — what is admitted and its evidence |
| [oracle.md](oracle.md) | oracle strategy + witnessed chrony 4.5 results; what was environmental |
| [version-lineage.md](version-lineage.md) | declared target version and the gap to newer chrony |
| [deployment-boundary.md](deployment-boundary.md) | the Stage 0–9 ladder and current position |
| [negative-capabilities.md](negative-capabilities.md) | what is deliberately not done yet |
| [source-archaeology.md](source-archaeology.md) | chrony semantics → C source → chrony-rs module |
| [packet-atlas.md](packet-atlas.md) | NTP wire-format byte court |
| [config-atlas.md](config-atlas.md) | config-parsing behavior court |
| [chronyc-parity.md](chronyc-parity.md) | `chronyc` output-parity court |
| [source-selection-atlas.md](source-selection-atlas.md) | reachability, selectability, falseticker intersection |
| [filtering-atlas.md](filtering-atlas.md) | sample filtering plan + implemented falseticker court |
| [security-boundary.md](security-boundary.md) | trust boundaries and unsafe ledger |

## Planned (scaffolding targets named in the doctrine)

`time-discipline-atlas.md`, `slew-step-atlas.md`, `drift-atlas.md`,
`nts-atlas.md`, `refclock-atlas.md`, `os-clock-ecology.md`,
`privilege-boundary.md`, `vendor-ecology.md`, `distro-defaults.md`,
`operational-knowledge.md`, `porting-lessons.md`.

These are written as their campaigns begin; an empty promise here is preferable to
a stale doc, so they are listed but not stubbed.
