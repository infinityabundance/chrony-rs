#!/usr/bin/env bash
# chrony-oracle-comparison.sh - Compare chrony-rs against real chronyd 4.5
#
# Sets up two Docker containers side by side:
#   chrony-oracle:  real chronyd 4.5 from Ubuntu repos
#   chrony-rs-test: chrony-rs daemon
#
# Then runs chronyc commands against both and captures differences.

set -euo pipefail

REPORT_DIR="/tmp/chrony-rs-oracle-comparison"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
SUMMARY="$REPORT_DIR/oracle-comparison-$TIMESTAMP.md"

CHRONYD_BIN="/tmp/chronyd-rs"
CHRONYC_BIN="/tmp/chronyc-rs"

echo "# chrony-rs vs real chronyd Oracle Comparison" > "$SUMMARY"
echo "Date: $(date)" >> "$SUMMARY"
echo "" >> "$SUMMARY"

# Create minimal config for real chrony
cat > /tmp/chrony-oracle.conf << 'CONF'
# Real chronyd test config
port 1123
cmdport 1323
local stratum 10
manual
log tracking
CONF

# Create minimal config for chrony-rs
cat > /tmp/chrony-rs.conf << 'CONF'
# chrony-rs test config  
port 2123
cmdport 2323
local stratum 10
manual
CONF

# Start real chronyd oracle
echo "=== Starting real chronyd oracle ==="
docker rm -f chrony-oracle 2>/dev/null || true
docker run -d --name chrony-oracle \
    --network chrony-test \
    -v /tmp/chrony-oracle.conf:/etc/chrony/chrony.conf:ro \
    ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq chrony && chronyd -d -n -f /etc/chrony/chrony.conf" \
    > "$REPORT_DIR/oracle-daemon.log" 2>&1 &

sleep 10

# Start chrony-rs daemon
echo "=== Starting chrony-rs daemon ==="
docker rm -f chrony-rs-daemon 2>/dev/null || true
docker run -d --name chrony-rs-daemon \
    --network chrony-test \
    -v "$CHRONYD_BIN:/chronyd-rs:ro" \
    -v /tmp/chrony-rs.conf:/etc/chrony/chrony.conf:ro \
    alpine:3.19 \
    /chronyd-rs -d -n -f /etc/chrony/chrony.conf \
    > "$REPORT_DIR/rs-daemon.log" 2>&1 &

sleep 3

# Get IPs
ORACLE_IP=$(docker inspect chrony-oracle --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
RS_IP=$(docker inspect chrony-rs-daemon --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")

echo "Oracle IP: $ORACLE_IP"
echo "chrony-rs IP: $RS_IP"

# Compare tracking output
echo "" >> "$SUMMARY"
echo "## tracking" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq chrony && chronyc -h $ORACLE_IP -p 1323 tracking" \
    2>/dev/null >> "$SUMMARY" || echo "Oracle tracking failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test \
    -v "$CHRONYC_BIN:/chronyc-rs:ro" \
    alpine:3.19 \
    /chronyc-rs -h $RS_IP -p 2323 tracking \
    2>/dev/null >> "$SUMMARY" || echo "chrony-rs tracking failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"

# Compare sources output
echo "## sources" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq chrony && chronyc -h $ORACLE_IP -p 1323 sources" \
    2>/dev/null >> "$SUMMARY" || echo "Oracle sources failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"

# Compare serverstats
echo "## serverstats" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq chrony && chronyc -h $ORACLE_IP -p 1323 serverstats" \
    2>/dev/null >> "$SUMMARY" || echo "Oracle serverstats failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test \
    -v "$CHRONYC_BIN:/chronyc-rs:ro" \
    alpine:3.19 \
    /chronyc-rs -h $RS_IP -p 2323 serverstats \
    2>/dev/null >> "$SUMMARY" || echo "chrony-rs serverstats failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"

# Compare activity
echo "## activity" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq chrony && chronyc -h $ORACLE_IP -p 1323 activity" \
    2>/dev/null >> "$SUMMARY" || echo "Oracle activity failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
docker run --rm --network chrony-test \
    -v "$CHRONYC_BIN:/chronyc-rs:ro" \
    alpine:3.19 \
    /chronyc-rs -h $RS_IP -p 2323 activity \
    2>/dev/null >> "$SUMMARY" || echo "chrony-rs activity failed" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo '```' >> "$SUMMARY"
echo "" >> "$SUMMARY"

# Cleanup
echo "" >> "$SUMMARY"
echo "## Cleanup" >> "$SUMMARY"
echo "Oracle container: chrony-oracle" >> "$SUMMARY"
echo "chrony-rs container: chrony-rs-daemon" >> "$SUMMARY"

docker rm -f chrony-oracle chrony-rs-daemon 2>/dev/null || true

echo ""
echo "=== Oracle comparison report saved to: $SUMMARY ==="
cat "$SUMMARY"
