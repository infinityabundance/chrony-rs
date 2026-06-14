# Port-parity method (chrony C ↔ chrony-rs)

This document explains how the 1:1 port-parity matrix in
[`docs/generated/port-parity.md`](generated/port-parity.md) is produced, and why
each side uses the tool it does. The matrix itself is **generated** — do not edit
it by hand; run `cargo xtask gen` and let the freshness gate enforce it.

> Headline, stated plainly: chrony 4.5 is **70 `.c` files / 1373 functions**
> (doxygen). chrony-rs today has *any* counterpart for **12** of those files and a
> *complete* port of **none**. This is an early-stage forensic reconstruction, and
> the matrix exists to keep that ratio honest rather than implied.

## Two sides, two tools — on purpose

Parity is a cross-language claim, so each side is inventoried with the tool that is
actually authoritative for that language.

### C side — doxygen (authoritative)

The chrony 4.5 C tree is indexed with **doxygen 1.9.8**, which has a real C
frontend. We run it over every `.c`/`.h` file (excluding `test/`) with
`EXTRACT_ALL`/`EXTRACT_STATIC` so even static functions are counted, emit XML, and
reduce it to a per-file function inventory. That inventory is committed, pinned to
an exact upstream commit, as
[`research/doxygen/chrony-4.5-c-inventory.tsv`](../research/doxygen/chrony-4.5-c-inventory.tsv).
The generator consumes the committed snapshot, so producing the matrix does **not**
require a chrony checkout — the heavy evidence stays reproducible, not vendored
(see [`research/doxygen/README.md`](../research/doxygen/README.md)).

### Rust side — `syn` AST (authoritative)

Doxygen has **no Rust frontend**. Its C++ lens misreads Rust and is not a
trustworthy inventory of the Rust code, so the Rust side is anchored natively with
the [`syn`](https://docs.rs/syn) AST in `xtask/src/parity.rs`: a `syn::visit::Visit`
walker counts every named function (`ItemFn` + `ImplItemFn` + `TraitItemFn`) and
every closure (`ExprClosure`). Walking the full tree — not just top-level items — is
what lets it count closures nested inside function bodies, the exact construct
doxygen drops. This is deterministic (a pure function of the source) so it fits the
freshness gate.

### ⚠️ Doxygen Rust-parsing limitation notice

> Doxygen's C++ frontend lacks native support for Rust's AST semantics. Run over
> the Rust crates (with `EXTENSION_MAPPING rs=C++`) it misparses `fn`, `impl`, and
> generics and reports anonymous, structurally incomplete members — e.g. it sees
> ~15 unnamed "functions" in `report.rs` where the AST shows named methods plus
> closures.
>
> **Mitigation.** The doxygen Rust run is retained only as a cross-language
> indexing artifact; it is **not** relied upon for any count or claim. The
> authoritative 1:1 Rust inventory is anchored natively via `syn` (above). Where a
> figure could come from either tool, the `syn` figure is the one used.

## What the matrix's columns mean

- **C fns** — doxygen's function count for that translation unit (the denominator).
- **status** — a curated, deliberately conservative judgment:
  - **◑ partial** — behavior from the file is ported *and admitted by a court* in
    [`reports/`](../reports/).
  - **○ scaffold** — a type or simulated stand-in exists, but chrony's behavior is
    not reproduced (e.g. a side-effect-free clock standing in for `local.c`).
  - **· none** — no counterpart. Files subsumed by the Rust std library
    (`array.c`, `memory.c`) or that are upstream test scaffolding (`stubs.c`) are
    marked none with a note, never counted as coverage.

When a file's coverage is ambiguous it is marked **down**, never up. Overclaiming
coverage is the single failure mode this project exists to prevent, so the matrix
errs toward understating it.

### Why function-count percentages are an *upper bound only*

The matrix reports a "loose upper bound on function coverage": the share of C
functions living in files that have *any* counterpart. It is explicitly an upper
bound — a file marked partial ports a fraction of its functions, so true
function-level coverage is well below that figure. chrony-rs ports **behavior under
court**, not functions 1:1 (a restoration, not a transliteration — see the README
doctrine), so the count is context, not the parity claim. The status column and its
court-backed notes are the claim.

## Regenerate

```sh
# 1. C inventory (only needed when bumping the pinned chrony version)
git clone --depth 1 --branch 4.5 https://github.com/mlichvar/chrony /tmp/chrony-src
#   run doxygen (GENERATE_XML=YES, EXTRACT_ALL/STATIC, OPTIMIZE_OUTPUT_FOR_C) and
#   reduce *_8c.xml -> research/doxygen/chrony-4.5-c-inventory.tsv
#   (recipe + Doxyfile in research/doxygen/README.md)

# 2. matrix (always; reads the committed TSV + the live Rust AST)
cargo xtask gen      # writes docs/generated/port-parity.md
cargo xtask check    # freshness gate (also run by the pre-commit hook)
```

## Extending coverage

When a new chrony behavior is ported under a court, update the `MAP` table in
`xtask/src/parity.rs` (role, counterpart modules, status, honesty note) and run
`cargo xtask gen`. The catalog is driven by the committed C inventory file set, so
a newly added or renamed upstream `.c` file shows up as an `(unmapped)` row until
it is cataloged — the matrix stays exhaustive by construction.
