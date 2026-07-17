#!/bin/sh
# Audit all unconditional `return true` statements in production code
# These may hide missing logic
cd "$(dirname "$0")/.."
echo "=== Audit: unconditional return true in crates/*/src/ ==="
grep -rn "return true" crates/*/src/ 2>/dev/null | grep -v test | grep -v "\./target" || echo "(none found)"
echo ""
echo "=== Potential audit items ==="
grep -rn "return true" crates/chrony-rs-core/src/ 2>/dev/null | grep -v test
