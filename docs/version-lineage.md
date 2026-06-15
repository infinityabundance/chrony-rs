# Version lineage

chrony behavior is not timeless; it must be measured against a specific version.
This page anchors `chrony-rs`'s declared target and tracks the gap to newer
releases.

## Declared target

- `TARGET_CHRONY_VERSION = 4.5` — the version we can actually run and witness in
  this environment (Ubuntu 24.04 `chrony 4.5-1ubuntu4.2`). See `oracle.md`.

The constant is asserted by a test in `lib.rs`; changing it means re-cutting the
oracle receipts under `reports/oracle/`, because witnessed claims are version-
anchored.

## Witnessed against 4.5

- Config acceptance and diagnostic phrasing (`chronyd -p`) — 7/7 fixtures, exact
  message text. See `oracle.md` and `config-atlas.md`.

## Not yet witnessed / version-sensitive

| Area | Note |
|------|------|
| `chronyc` output format | layout reconstructed; not yet against live 4.5 (environmental, see `oracle.md`) |
| NTP packet/measurement | RFC-anchored, largely version-stable, but chrony refid/kiss policy can shift |
| Source selection | algorithmic reconstruction; chrony's selector has changed across versions |
| NTS, refclock | not implemented; strongly version- and build-flag-dependent |

## Toward newer chrony (4.6+)

4.6 was the original aspirational target. Promoting to 4.6 requires:

1. an environment with chrony 4.6 installed,
2. re-running `tools/oracle/capture-config.sh` and any future oracle harnesses,
3. recording deltas here (new/changed directives, message changes, selector
   tweaks) as a version-diff, not a silent retarget.

Build flags matter too: the 4.5 oracle here is built with `+NTS +REFCLOCK +RTC
+PRIVDROP +SCFILTER`. A differently-configured package may parse/accept different
directives; that is a `vendor-ecology.md` concern.
