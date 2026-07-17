#!/bin/sh
# Capture a chronyd NTP trace for the oracle comparison court.
#
# Usage: tools/oracle/capture-trace.sh [--conf <config>] [--duration <secs>] [--output <path>]
#
# Requires: chronyd 4.5, cargo xtask
#
# Run on a host WITH chronyd installed. This script:
#   1. Starts chronyd with the given config in debug mode
#   2. Sends a few NTP queries with chronyc to exercise the SourceInstance pipeline
#   3. Captures the resulting trace JSON
#   4. Stops chronyd

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CHRONYD="${CHRONYD:-chronyd}"
CONF="$REPO_ROOT/tools/oracle/config-fixtures/valid_minimal.conf"
DURATION=10
OUTPUT="$REPO_ROOT/research/oracle/captured-trace.json"
POSITIONAL_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --conf|--config) CONF="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --help|-h) echo "usage: $0 [--conf <config>] [--duration <secs>] [--output <path>]"; exit 0 ;;
        --) shift; break ;;
        -*)
            echo "error: unknown option: $1"
            echo "usage: $0 [--conf <config>] [--duration <secs>] [--output <path>]"
            exit 2 ;;
        *) POSITIONAL_ARGS="$POSITIONAL_ARGS $1"; shift ;;
    esac
done

# If positional args remain after --, preserve them
set -- "$@"
[ -z "$POSITIONAL_ARGS" ] || set -- $POSITIONAL_ARGS "$@"

echo "capture-trace: chronyd=$CHRONYD config=$CONF duration=${DURATION}s output=$OUTPUT"

# Verify chronyd exists
if ! command -v "$CHRONYD" >/dev/null 2>&1; then
    echo "ERROR: chronyd not found at '$CHRONYD' and not in PATH."
    echo "  Install chrony 4.5 first:"
    echo "    Debian/Ubuntu: sudo apt install chrony"
    echo "    Fedora:        sudo dnf install chrony"
    echo "    Arch:          sudo pacman -S chrony"
    exit 1
fi

# Capture the trace using xtask
cd "$REPO_ROOT"
cargo xtask capture-trace \
    --chronyd "$CHRONYD" \
    --config "$CONF" \
    --output "$OUTPUT" \
    --duration "$DURATION" \
    "$@"

echo ""
echo "Done. Trace written to: $OUTPUT"
echo "To compare against chrony-rs, run:"
echo "  cargo run --release --bin chronyd-rs -- --replay-trace $OUTPUT"
