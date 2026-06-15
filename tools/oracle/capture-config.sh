#!/usr/bin/env bash
# Config oracle: differential capture of `chronyd -p` (the primary oracle) versus
# `chronyd-rs --check-config`, over the fixtures in tools/oracle/config-fixtures/.
#
# `chronyd -p` parses a config and either echoes it (exit 0) or prints a fatal
# error and exits 1. That makes it a clean, deterministic oracle for config
# acceptance and diagnostics — no clock, no network, no daemon. We normalize away
# the only non-deterministic parts of chrony's stderr (the leading timestamp and
# the absolute file path) so the comparable text is stable across runs and hosts.
#
# Output: a per-fixture receipt and a summary table under reports/oracle/config/.
# Exit non-zero if chrony-rs and chrony disagree on ACCEPT/REJECT for any fixture
# (message-text parity is reported but not yet enforced — see docs/config-atlas.md).
set -uo pipefail
cd "$(dirname "$0")/../.."

ORACLE_BIN="${CHRONYD:-chronyd}"
FIXTURES="tools/oracle/config-fixtures"
OUT="reports/oracle/config"
mkdir -p "$OUT"

if ! command -v "$ORACLE_BIN" >/dev/null 2>&1; then
    echo "error: oracle '$ORACLE_BIN' not found; install chrony or set CHRONYD" >&2
    exit 2
fi
ORACLE_VER="$("$ORACLE_BIN" --version 2>&1 | head -1)"

cargo build -q --release
RS_BIN="target/release/chronyd-rs"

# Strip chrony's timestamp prefix and absolute path so the diagnostic text is
# stable: "<ts> Fatal error : <msg> at line N in file <path>" -> "Fatal error :
# <msg> at line N in file <FILE>".
normalize_chrony() {
    sed -E 's/^[0-9T:-]+Z //; s| in file [^ ]+$| in file <FILE>|'
}

SUMMARY="$OUT/SUMMARY.md"
{
    echo "# Config oracle differential ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo
    echo "Oracle: \`$ORACLE_VER\`"
    echo
    echo "| Fixture | chrony exit | chrony-rs exit | accept agree | chrony diagnostic (normalized) |"
    echo "|---------|------------:|---------------:|:------------:|--------------------------------|"
} > "$SUMMARY"

disagreements=0
for f in "$FIXTURES"/*.conf; do
    name="$(basename "$f")"

    chrony_err="$("$ORACLE_BIN" -p -f "$f" 2>&1 >/dev/null | normalize_chrony)"
    "$ORACLE_BIN" -p -f "$f" >/dev/null 2>&1; chrony_exit=$?

    "$RS_BIN" --check-config "$f" >/dev/null 2>&1; rs_exit=$?

    # ACCEPT == exit 0; REJECT == non-zero. We compare the class, not the code,
    # because chrony uses 1 for config errors while chrony-rs distinguishes 1
    # (config error) from 2 (IO/usage) — both are REJECT for this comparison.
    chrony_accept=$([ "$chrony_exit" -eq 0 ] && echo accept || echo reject)
    rs_accept=$([ "$rs_exit" -eq 0 ] && echo accept || echo reject)
    if [ "$chrony_accept" = "$rs_accept" ]; then agree="yes"; else agree="**NO**"; disagreements=$((disagreements+1)); fi

    diag="${chrony_err:-(none)}"
    echo "| $name | $chrony_exit | $rs_exit | $agree | \`$diag\` |" >> "$SUMMARY"

    # Per-fixture receipt with full captured bytes.
    {
        echo "fixture: $name"
        echo "oracle: $ORACLE_VER"
        echo "chrony_exit: $chrony_exit"
        echo "chrony_stderr_normalized: $diag"
        echo "chrony_rs_exit: $rs_exit"
        echo "accept_agree: $agree"
    } > "$OUT/$name.receipt"
done

echo >> "$SUMMARY"
echo "Disagreements on accept/reject: $disagreements" >> "$SUMMARY"

cat "$SUMMARY"
exit "$disagreements"
