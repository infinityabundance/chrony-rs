#!/usr/bin/env bash
# Regenerate byte-parity receipt artifacts under reports/ and print their hashes.
#
# This is the reproducibility contract behind reports/receipts/RECEIPTS.md: any
# engineer, on any machine, runs this and gets identical bytes and identical
# SHA-256 values. A diff here is a real parity regression, not noise.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -q
D=target/release/chronyd-rs
C=target/release/chronyc-rs

mkdir -p reports/chronyc reports/config

"$C" render-tracking crates/chronyc-rs/tests/fixtures/tracking.json \
    > reports/chronyc/tracking.sample.out
"$D" --check-config examples/minimal.conf \
    > reports/config/check-config.minimal.out 2>&1

echo "Regenerated. Hashes:"
sha256sum \
    reports/chronyc/tracking.sample.out \
    reports/config/check-config.minimal.out
