# Oracle strategy and witnessed results

The primary oracle for chrony-specific behavior is **real `chronyd`**. This page
records what has actually been captured, against which version, and how to
reproduce it — plus what could *not* be captured in this environment and why.

## Available oracle

- **chrony 4.5** (`chronyd (chrony) version 4.5 +CMDMON +NTP +REFCLOCK +RTC
  +PRIVDROP +SCFILTER +SIGND +ASYNCDNS +NTS +SECHASH +IPV6 -DEBUG`), Ubuntu
  24.04 package `4.5-1ubuntu4.2`.

Because 4.5 is the version we can actually *witness*, `TARGET_CHRONY_VERSION` is
anchored to `4.5`. Targeting a version we cannot run would be an unanchored claim.
The path to newer versions is tracked in `version-lineage.md`.

## Config diagnostics — ORACLE-WITNESSED

`chronyd -p -f <file>` parses a config and either echoes it (exit 0) or prints a
fatal error and exits 1. No clock, no network, no daemon — a clean, deterministic
oracle for config acceptance and diagnostics.

`tools/oracle/capture-config.sh` runs `chronyd -p` and `chronyd-rs --check-config`
over `tools/oracle/config-fixtures/` and compares. Captured result (receipts under
`reports/oracle/config/`):

- **8/8 fixtures agree on accept/reject** with chrony 4.5 — 0 disagreements
  (including the real Ubuntu 24.04 default config; see `distro-defaults.md`).
- chrony-rs reproduces chrony 4.5's **exact diagnostic phrasing** (normalized for
  the host-specific timestamp prefix and absolute path):

  | input | chrony 4.5 / chrony-rs message |
  |-------|--------------------------------|
  | `frobnicate 5` | `Fatal error : Invalid directive at line 1 in file <FILE>` |
  | `server` | `Fatal error : Could not parse server directive at line 1 in file <FILE>` |
  | `makestep fast 3` | `Fatal error : Could not parse makestep directive at line 1 in file <FILE>` |
  | `driftfile` | `Fatal error : Missing arguments for driftfile directive at line 1 in file <FILE>` |
  | `rtcsync foo` | `Fatal error : Too many arguments for rtcsync directive at line 1 in file <FILE>` |

  This phrasing is produced by `Diagnostic::chrony_message()` and pinned by
  `diagnostics_match_witnessed_chrony_4_5_messages` in `config/parser.rs`.

## Directive recognition — ORACLE-WITNESSED

`tools/oracle/directive-recognition.sh` probes every keyword in chrony-rs's
`KNOWN_DIRECTIVES` against `chronyd -p` (an unknown keyword yields "Invalid
directive"; a known one yields a different error). Result: **all 82 entries are
recognized by chrony 4.5** (receipt: `reports/oracle/config/directive-recognition.md`).

This harness caught **five fabricated entries** in chrony-rs's original list —
guessed NTS names (`ntsca`, `ntscert`, `ntskey`) and nonexistent `open_commands`
/`ntpcache` — and the correct names (`ntsservercert`, `ntsserverkey`,
`ntstrustedcerts`, `ntscachedir`, `sourcedir`, `cmdratelimit`, `refresh`) were
learned from the oracle. The set is now measured, not guessed, and pinned by
`known_directive_set_is_oracle_anchored_to_chrony_4_5` in `config/parser.rs`.

### Admitted divergence (documented, not hidden)

chrony fails **fatally on the first** bad directive and emits exactly one error.
chrony-rs **collects all** diagnostics and reports them. Each individual line
matches chrony's wording, and the accept/reject exit-code class matches. The
multi-error behavior is a deliberate, more-helpful divergence, not a parity bug.

## Live `chronyc` output — ENVIRONMENTAL (not captured here)

Capturing real `chronyc tracking`/`sources` output requires a persistent running
`chronyd` with a control socket. In this sandboxed build environment `chronyd`
does not stay resident (the daemon exits immediately under the process/sandbox
constraints), so live control-socket output could **not** be witnessed here.

This is classified as **environmental**, per doctrine — not a chrony-rs limitation
and not silently skipped. The `chronyc tracking` *layout* court (`CHRONYC.1`)
therefore remains validated against a reconstructed fixture, not yet against a
live 4.5 daemon. Reproducing it needs an environment where `chronyd -x` can run
resident; the steps are in `tools/oracle/` for when one is available.

## Reproducing

```sh
sudo apt-get install -y chrony              # provides the 4.5 oracle here
bash tools/oracle/capture-config.sh         # accept/reject + diagnostic differential
bash tools/oracle/directive-recognition.sh  # KNOWN_DIRECTIVES vs chrony's recognized set
```
Both exit non-zero on any disagreement.

Receipts land under `reports/oracle/config/` (a per-fixture `.receipt` and
`SUMMARY.md`).
