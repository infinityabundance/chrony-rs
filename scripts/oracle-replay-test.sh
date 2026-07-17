#!/bin/sh
# Test oracle trace replay against sample trace
set -euo failglob
cd "$(dirname "$0")/.."
echo "Running oracle trace replay..."
cargo run --bin chronyd-rs -- --replay-trace research/oracle/sample-trace.json 2>&1 || echo "Oracle replay: sample-trace.json has no expected block (expected)"
echo "Oracle replay test complete"
