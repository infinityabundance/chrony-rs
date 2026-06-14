# Config atlas

Behavior court for chrony configuration parsing. Implemented in
`chrony-rs-core/src/config/`.

## Grammar reproduced

chrony configs are line-oriented: each non-blank, non-comment line is a directive
keyword followed by whitespace-separated arguments. Key fidelity points (all
witnessed against chrony 4.5):

- Directive keywords match **case-insensitively** (chrony uses `strcasecmp`).
- A line is a **comment only when its first non-whitespace character** is one of
  `# % ! ;` — **not** mid-line. `server host iburst # primary` is an *error*
  (chrony parses `#` as an argument), and `host#1` keeps the `#1`. An earlier
  lexer stripped mid-line `#` and silently accepted configs chrony rejects; the
  oracle caught it. See `config::lexer::COMMENT_CHARS`.
- Leading whitespace is insignificant; blank/comment-only lines yield nothing.
- Directive **order is preserved** — later single-valued directives win.
- The recognized directive set is **93 entries**, extracted from `conf.c` and
  oracle-verified (see "Recognized vs modeled" below).

## Source-directive options (1:1 with chrony 4.5)

`server`/`pool`/`peer` options are validated exactly as
`cmdparse.c::CPS_ParseNTPSourceAdd` does: flag options consume nothing, value
options consume one word, and any **unknown option** (or value option missing its
value) is rejected as `Could not parse <kw> directive` — matching chrony. The
flag/value/select option tables are extracted from the C source
(`research/source-archaeology/`) and exposed via
`config::source_flag_options()` / `source_value_options()`.

## Recognized vs modeled

Two distinct sets, deliberately kept apart:

- **Recognized** — every directive in chrony's dispatch table for the target
  version. A file using only recognized directives passes `--check-config`.
- **Modeled** — directives given typed semantics (currently `server`, `pool`,
  `peer`, `driftfile`, `makestep`, `rtcsync`). Everything else is preserved as
  `Directive::Unmodeled` with no diagnostic.

An **unknown** directive (not in the recognized set) is a fatal error
(`CFG_UNKNOWN_DIRECTIVE`), matching chrony's rejection.

The recognized set (`KNOWN_DIRECTIVES`, 93 entries) is **oracle-anchored to chrony
4.5**: every entry is verified recognized by `chronyd -p` via
`tools/oracle/directive-recognition.sh`. The oracle caught five fabricated entries
in the original hand-written list — see `oracle.md`.

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
| 13 | distro default configs | **oracle-witnessed** — Ubuntu 24.04 default accepted, matches chrony 4.5 (`distro-defaults.md`) |
| 14 | exact diagnostic parity | **oracle-witnessed against chrony 4.5** for 5 error classes (see below) |

## Oracle-witnessed diagnostics (chrony 4.5)

`tools/oracle/capture-config.sh` compared `chronyd-rs --check-config` against
`chronyd -p` over `tools/oracle/config-fixtures/`: **0 disagreements** on
accept/reject, and `Diagnostic::chrony_message()` reproduces chrony 4.5's exact
phrasing for these classes (normalized for timestamp/path):

- `Fatal error : Invalid directive at line N in file <FILE>`
- `Fatal error : Could not parse <kw> directive at line N in file <FILE>`
- `Fatal error : Missing arguments for <kw> directive at line N in file <FILE>`
- `Fatal error : Too many arguments for <kw> directive at line N in file <FILE>`

Pinned by `diagnostics_match_witnessed_chrony_4_5_messages` (`config/parser.rs`)
and receipts under `reports/oracle/config/`. See `docs/oracle.md`.

### Admitted divergence

chrony fails fatally on the **first** bad directive (one message); chrony-rs
**collects all** diagnostics. Each line matches chrony's wording and the
accept/reject class matches — the multi-error behavior is a deliberate, more
helpful divergence.

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
