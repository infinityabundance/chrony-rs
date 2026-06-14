# Config atlas

Behavior court for chrony configuration parsing. Implemented in
`chrony-rs-core/src/config/`.

## Grammar reproduced

chrony configs are line-oriented: each non-blank, non-comment line is a directive
keyword followed by whitespace-separated arguments. Key fidelity points:

- Directive keywords match **case-insensitively** (chrony uses `strcasecmp`).
- `#` begins a comment **only at a token boundary**; `host#1` keeps the `#1`.
- Leading whitespace is insignificant; blank/comment-only lines yield nothing.
- Directive **order is preserved** — later single-valued directives win.

## Recognized vs modeled

Two distinct sets, deliberately kept apart:

- **Recognized** — every directive in chrony's dispatch table for the target
  version. A file using only recognized directives passes `--check-config`.
- **Modeled** — directives given typed semantics (currently `server`, `pool`,
  `peer`, `driftfile`, `makestep`, `rtcsync`). Everything else is preserved as
  `Directive::Unmodeled` with no diagnostic.

An **unknown** directive (not in the recognized set) is a fatal error
(`CFG_UNKNOWN_DIRECTIVE`), matching chrony's rejection.

## Court status (`CHRONY.CONFIG.*`)

| ID | Description | Status |
|----|-------------|--------|
| 1 | lexical parsing | admitted |
| 2 | comments/blank lines | admitted |
| 3 | server directives | admitted |
| 4 | pool directives | admitted |
| 5 | peer directives | admitted (parsed; semantics deferred) |
| 6 | refclock directives | deferred (recognized, unmodeled) |
| 7 | makestep | partial (2-arg form admitted; bare form deferred) |
| 8 | driftfile | admitted |
| 9 | allow/deny | deferred (recognized, unmodeled) |
| 10 | bind/address options | deferred (recognized, unmodeled) |
| 11 | nts options | deferred (recognized, unmodeled) |
| 12 | invalid directive diagnostics | admitted (`CFG_UNKNOWN_DIRECTIVE`) |
| 13 | distro default configs | planned |
| 14 | exact/normalized diagnostic parity | normalized (exact text pending oracle) |

## Diagnostic codes

Stable machine codes are the contract; message *text* is normalized until
witnessed against chrony's exact output (`CHRONY.CONFIG.14`):

`CFG_UNKNOWN_DIRECTIVE`, `CFG_MISSING_ADDRESS`, `CFG_MISSING_PATH`,
`CFG_MISSING_VALUE`, `CFG_BAD_NUMBER`, `CFG_BAD_ARITY`, `CFG_UNEXPECTED_ARGS`.

## Exit-code parity

`chronyd-rs --check-config`:

- `0` — clean
- `1` — configuration has error diagnostics
- `2` — usage error or config file could not be read

The 1-vs-2 split (config error vs IO/usage) is deliberate and tested in
`chronyd-rs/tests/cli.rs`.
