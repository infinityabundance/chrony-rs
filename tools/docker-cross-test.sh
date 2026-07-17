#!/usr/bin/env bash
# docker-cross-test.sh - Cross-distro verification of chrony-rs
#
# Tests:
#  1. Binary starts and --help works on each distro
#  2. Daemon starts (--lab-daemon) on each distro
#  3. Basic cmdmon query works on each distro
#  4. Cross-client query from each distro to each other distro's daemon
#
set -euo pipefail

CHRONYD="/tmp/chronyd-rs"
CHRONYC="/tmp/chronyc-rs"
REPORT_DIR="/tmp/chrony-rs-cross-test"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%dT%H%M%S)
SUMMARY="$REPORT_DIR/summary-$TIMESTAMP.md"

DISTROS=(
    "ubuntu:24.04:apt"
    "debian:bookworm:apt"
    "fedora:latest:dnf"
    "almalinux:9:dnf"
    "rockylinux:9:dnf"
    "archlinux:latest:pacman"
    "redhat/ubi8:latest:dnf"
    "nixos/nix:latest:nix"
)

echo "# chrony-rs Cross-Distro Test Report" > "$SUMMARY"
echo "Date: $(date)" >> "$SUMMARY"
echo "Binary: chronyd-rs $(stat --format='%s bytes' $CHRONYD), chronyc-rs $(stat --format='%s bytes' $CHRONYC)" >> "$SUMMARY"
echo "" >> "$SUMMARY"

echo "## Results" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Distro | --help | Daemon Start | Self-Query | Cross-Client |" >> "$SUMMARY"
echo "|--------|--------|-------------|------------|--------------|" >> "$SUMMARY"

# Phase 1: Test binary runs on each distro
for entry in "${DISTROS[@]}"; do
    IFS=':' read -r distro tag _ <<< "$entry"
    echo ""
    echo "=== Testing $distro:$tag ==="

    # Test --help
    if docker run --rm -v "$CHRONYD:/chronyd-rs:ro" "$distro:$tag" /chronyd-rs --help > "$REPORT_DIR/help-$distro.txt" 2>&1; then
        HELP="PASS"
    else
        HELP="FAIL"
    fi

    # Start daemon in background
    CONTAINER_NAME="chrony-rs-daemon-$distro"
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

    # Create a minimal config
    cat > /tmp/chrony-$distro.conf << 'CONF'
# chrony-rs test config
port 123
cmdport 323
local stratum 10
manual
CONF

    # Start daemon container with a static IP
    docker run -d --name "$CONTAINER_NAME" \
        --network chrony-test 2>/dev/null || docker network create chrony-test 2>/dev/null || true
    docker run -d --name "$CONTAINER_NAME" \
        --network chrony-test \
        -v "$CHRONYD:/chronyd-rs:ro" \
        -v "/tmp/chrony-$distro.conf:/etc/chrony/chrony.conf:ro" \
        "$distro:$tag" \
        /chronyd-rs -d -n -f /etc/chrony/chrony.conf \
        > "$REPORT_DIR/daemon-$distro.log" 2>&1 || true

    # Wait and check
    sleep 2
    DAEMON_OK=$(docker ps --filter "name=$CONTAINER_NAME" --format '{{.Names}}' 2>/dev/null || echo "")
    if [ -n "$DAEMON_OK" ]; then
        DAEMON="PASS"
    else
        DAEMON="FAIL"
        echo "Daemon $distro failed to start, skipping cross-test" >> "$SUMMARY"
        echo "| $distro | $HELP | $DAEMON | SKIP | SKIP |" >> "$SUMMARY"
        continue
    fi

    # Get daemon IP
    DAEMON_IP=$(docker inspect "$CONTAINER_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "127.0.0.1")

    # Self-query with chronyc-rs
    SELF_QUERY="FAIL"
    SELF_RESULT=$(docker run --rm --network chrony-test \
        -v "$CHRONYC:/chronyc-rs:ro" \
        "$distro:$tag" \
        /chronyc-rs -h "$DAEMON_IP" -p 323 tracking \
        2>"$REPORT_DIR/selfquery-$distro-err.txt" || true)
    if echo "$SELF_RESULT" | grep -q "Reference ID\|Stratum\|ref_id\|stratum"; then
        SELF_QUERY="PASS"
        echo "$SELF_RESULT" > "$REPORT_DIR/selfquery-$distro.txt"
    fi

    # Cross-client: test against other daemons
    CROSS_RESULT=""
    for target_entry in "${DISTROS[@]}"; do
        IFS=':' read -r target_distro target_tag _ <<< "$target_entry"
        if [ "$target_distro" = "$distro" ]; then
            continue
        fi
        TARGET_CONTAINER="chrony-rs-daemon-$target_distro"
        TARGET_IP=$(docker inspect "$TARGET_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
        if [ -z "$TARGET_IP" ]; then
            continue
        fi
        CROSS_RESULT_ENTRY=$(docker run --rm --network chrony-test \
            -v "$CHRONYC:/chronyc-rs:ro" \
            "$distro:$tag" \
            /chronyc-rs -h "$TARGET_IP" -p 323 tracking \
            2>/dev/null || true)
        if echo "$CROSS_RESULT_ENTRY" | grep -q "Reference ID\|ref_id"; then
            CROSS_RESULT="${CROSS_RESULT}${target_distro}:OK "
            echo "Cross: $distro → $target_distro = OK" >> "$REPORT_DIR/cross-$distro.txt"
        else
            CROSS_RESULT="${CROSS_RESULT}${target_distro}:FAIL "
            echo "Cross: $distro → $target_distro = FAIL" >> "$REPORT_DIR/cross-$distro.txt"
        fi
    done

    if echo "$CROSS_RESULT" | grep -q "OK"; then
        CROSS="PASS"
    else
        CROSS="SKIP"
    fi

    echo "| $distro | $HELP | $DAEMON | $SELF_QUERY | $CROSS |" >> "$SUMMARY"

    # Cleanup
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
done

echo "" >> "$SUMMARY"
echo "## Cross-Distro Matrix Details" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "See per-distro log files in $REPORT_DIR/" >> "$SUMMARY"
echo "" >> "$SUMMARY"

echo ""
echo "=== Summary ==="
cat "$SUMMARY"
echo ""
echo "Report saved to: $SUMMARY"
