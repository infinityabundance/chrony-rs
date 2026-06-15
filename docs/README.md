# chrony-rs documentation archive

The operational-knowledge half of the project. The crate stays lean; this archive
preserves the reasoning, courts, and ecology maps.

## Present

| Doc | Purpose |
|-----|---------|
| [generated/status.md](generated/status.md) | **machine-generated** facts (`cargo xtask gen`); freshness-gated |
| [architecture.md](architecture.md) | workspace layout, trait boundaries, design rationale |
| [compatibility.md](compatibility.md) | the court matrix — what is admitted and its evidence |
| [oracle.md](oracle.md) | oracle strategy + witnessed chrony 4.5 results; what was environmental |
| [version-lineage.md](version-lineage.md) | declared target version and the gap to newer chrony |
| [distro-defaults.md](distro-defaults.md) | shipped distro configs witnessed (Ubuntu 24.04) |
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
`privilege-boundary.md`, `vendor-ecology.md`,
`operational-knowledge.md`, `porting-lessons.md`.

These are written as their campaigns begin; an empty promise here is preferable to
a stale doc, so they are listed but not stubbed.

## Freshness gate

Machine-derivable facts (target version, the recognized-directive set, source-option
tables, `unsafe` count, oracle fixture inventory) live in
[`generated/status.md`](generated/status.md), produced by `cargo xtask gen` from
the code — the single source of truth. [`negative-capabilities.md`](negative-capabilities.md)
is **also generated**: its "implemented modules" list is derived from the port-parity
matrix, so it can never claim an implemented module is absent. The workspace root
README and all four crate READMEs (`crates/*/README.md`) are generated too — the umbrella/core
crate ported-unit lists come straight from the parity matrix.

Two enforcement layers run in `cargo xtask check` (via the pre-commit hook
`.githooks/pre-commit`, activate with `git config core.hooksPath .githooks`):

1. **Generated-doc freshness** — a byte diff refuses any commit whose
   `docs/generated/*` or `docs/negative-capabilities.md` is stale.
2. **Pinned doc facts** — every *living* doc that restates a machine fact is
   checked to still contain its live value: the target chrony version, the
   recognized directive count, the chrony source inventory totals, and the
   `unsafe` count, each pinned in **all** the docs that mention them
   (`asserted_facts()` in `xtask/src/main.rs`). A doc that drifts from the code
   fails the gate. New drift-prone claims must be added to this set (or the doc
   made generated) rather than left ungated.

Evidence receipts under [`../reports/`](../reports/) and
[`../research/`](../research/) are deliberately **not** pinned: they are frozen
snapshots of what was witnessed at a specific version/commit and must keep stating
the values they actually recorded, even after the live target moves on.

This is the "no stale docs, generated *or* prose" doctrine, enforced.
