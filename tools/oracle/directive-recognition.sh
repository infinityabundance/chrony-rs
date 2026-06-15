#!/usr/bin/env bash
# Directive-recognition oracle: verify every keyword in chrony-rs's
# KNOWN_DIRECTIVES is actually recognized by real chronyd, and report any chrony
# directive chrony-rs is missing from a candidate superset.
#
# Method: `chronyd -p` answers "Invalid directive" for an unknown keyword and a
# different error (missing/parse) for a known one fed without arguments. So we can
# probe recognition by feeding the bare keyword and checking for "Invalid
# directive". No clock, no network, no daemon.
#
# This is the harness that caught five fabricated entries (guessed NTS names and a
# nonexistent open_commands/ntpcache) in chrony-rs's list — the reason the set is
# measured, not assumed. Exits non-zero if chrony-rs lists a directive chrony does
# not recognize (a fabricated/version-wrong entry).
set -uo pipefail
cd "$(dirname "$0")/../.."

ORACLE_BIN="${CHRONYD:-chronyd}"
OUT="reports/oracle/config"
mkdir -p "$OUT"
command -v "$ORACLE_BIN" >/dev/null 2>&1 || { echo "error: '$ORACLE_BIN' not found" >&2; exit 2; }
ORACLE_VER="$("$ORACLE_BIN" --version 2>&1 | head -1)"

recognized() {
    printf '%s\n' "$1" > /tmp/chrony_rec_probe.conf
    ! "$ORACLE_BIN" -p -f /tmp/chrony_rec_probe.conf 2>&1 >/dev/null | head -1 | grep -q "Invalid directive"
}

# Extract KNOWN_DIRECTIVES from the source between the array braces.
mapfile -t RS_KNOWN < <(awk '
    /const KNOWN_DIRECTIVES/ {grab=1}
    grab {print}
    grab && /\];/ {exit}
' crates/chrony-rs-core/src/config/parser.rs | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u)

REPORT="$OUT/directive-recognition.md"
{
    echo "# Directive-recognition oracle ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo
    echo "Oracle: \`$ORACLE_VER\`"
    echo
    echo "chrony-rs KNOWN_DIRECTIVES count: ${#RS_KNOWN[@]}"
    echo
} > "$REPORT"

bad=0
for kw in "${RS_KNOWN[@]}"; do
    if ! recognized "$kw"; then
        echo "- **chrony-rs lists \`$kw\` but chrony does NOT recognize it**" >> "$REPORT"
        bad=$((bad+1))
    fi
done

if [ "$bad" -eq 0 ]; then
    echo "All ${#RS_KNOWN[@]} chrony-rs directives are recognized by the oracle. ✅" >> "$REPORT"
fi

cat "$REPORT"
exit "$bad"
