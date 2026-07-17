#!/bin/sh
# Soak test: run chronyd-rs --lab-daemon for N hours and check stability
set -euo pipefail
DURATION="${1:-1}"
echo "Running soak test for ${DURATION}h..."
# Start chronyd-rs in lab mode
timeout "${DURATION}h" cargo run --bin chronyd-rs -- --lab-daemon 3232 &
PID=$!
sleep 5
# Poll tracking data periodically
for i in $(seq 1 $((DURATION * 12))); do
    sleep 300  # 5 min intervals
    echo "=== Check $i at $(date) ==="
    # Check it's still running
    if ! kill -0 $PID 2>/dev/null; then
        echo "FAIL: chronyd-rs died"
        exit 1
    fi
done
wait $PID
echo "PASS: soak test completed"
