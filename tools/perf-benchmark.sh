#!/usr/bin/env bash
# perf-benchmark.sh - Real performance measurements for chrony-rs
set -euo pipefail

CHRONYD="target/x86_64-unknown-linux-musl/release/chronyd-rs"
CHRONYC="target/x86_64-unknown-linux-musl/release/chronyc-rs"
REPORT_DIR="/tmp/chrony-rs-perf-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$REPORT_DIR"
SUMMARY="$REPORT_DIR/summary.md"

DISTROS=("alpine:3.19" "ubuntu:24.04" "debian:bookworm" "fedora:latest")

cat > "$SUMMARY" << HEADER
# chrony-rs Performance Characteristics

> **Live measurements** gathered on $(date) across Docker cross-distro matrix.
> Methodology: each value is the median of 3 runs unless noted.

HEADER

# ---- Phase 1: Binary size ----
echo "## 1. Binary Size" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Binary | Size (stripped musl) |" >> "$SUMMARY"
echo "|--------|--------------------|" >> "$SUMMARY"
CHRONYD_SIZE=$(stat --format='%s' "$CHRONYD" 2>/dev/null || echo "0")
CHRONYC_SIZE=$(stat --format='%s' "$CHRONYC" 2>/dev/null || echo "0")
echo "| chronyd-rs | $(numfmt --to=iec $CHRONYD_SIZE 2>/dev/null || echo "${CHRONYD_SIZE}B") |" >> "$SUMMARY"
echo "| chronyc-rs | $(numfmt --to=iec $CHRONYC_SIZE 2>/dev/null || echo "${CHRONYC_SIZE}B") |" >> "$SUMMARY"
echo "" >> "$SUMMARY"

# ---- Phase 2: Daemon startup time ----
echo "## 2. Daemon Startup Time (cold start, median of 3)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Distro | Time |" >> "$SUMMARY"
echo "|--------|------|" >> "$SUMMARY"

docker network rm chrony-perf 2>/dev/null || true
docker network create chrony-perf 2>/dev/null || true

for entry in "${DISTROS[@]}"; do
    distro="${entry%%:*}"
    tag="${entry##*:}"
    TIMES=()
    for i in 1 2 3; do
        start=$(date +%s%N)
        cid=$(docker run -d --network chrony-perf \
            -v "$(pwd)/$CHRONYD:/chronyd-rs:ro" \
            -v /tmp/chrony-matrix.conf:/etc/chrony/chrony.conf:ro \
            "$distro:$tag" /chronyd-rs -d -n -f /etc/chrony/chrony.conf 2>/dev/null) || { TIMES+=("FAIL"); continue; }
        for j in $(seq 1 30); do
            if docker logs "$cid" 2>&1 | grep -q "entering event loop"; then
                break
            fi
            sleep 0.2
        done
        end=$(date +%s%N)
        elapsed_ms=$(( (end - start) / 1000000 ))
        TIMES+=("$elapsed_ms")
        docker rm -f "$cid" >/dev/null 2>&1 || true
    done
    # Filter out FAILs, take median
    GOOD=()
    for t in "${TIMES[@]}"; do
        if [ "$t" != "FAIL" ]; then GOOD+=("$t"); fi
    done
    if [ ${#GOOD[@]} -gt 0 ]; then
        IFS=$'\n' sorted=($(sort -n <<<"${GOOD[*]}")); unset IFS
        mid=$(( ${#sorted[@]} / 2 ))
        echo "| $distro | ${sorted[$mid]}ms |" >> "$SUMMARY"
    else
        echo "| $distro | FAIL |" >> "$SUMMARY"
    fi
done

# ---- Phase 3: chronyc-rs command latency ----
echo "" >> "$SUMMARY"
echo "## 3. chronyc-rs Command Latency (median of 3)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Distro | tracking | serverstats | activity | n_sources |" >> "$SUMMARY"
echo "|--------|----------|-------------|----------|-----------|" >> "$SUMMARY"

DAEMON_CID=$(docker run -d --network chrony-perf \
    -v "$(pwd)/$CHRONYD:/chronyd-rs:ro" \
    -v /tmp/chrony-matrix.conf:/etc/chrony/chrony.conf:ro \
    alpine:3.19 /chronyd-rs -d -n -f /etc/chrony/chrony.conf 2>/dev/null)
sleep 3
DAEMON_IP=$(docker inspect "$DAEMON_CID" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "172.20.0.2")

for entry in "${DISTROS[@]}"; do
    distro="${entry%%:*}"
    tag="${entry##*:}"
    LINE="| $distro"
    for cmd in tracking serverstats activity n_sources; do
        TIMES=()
        for i in 1 2 3; do
            start=$(date +%s%N)
            docker run --rm --network chrony-perf \
                -v "$(pwd)/$CHRONYC:/chronyc-rs:ro" \
                "$distro:$tag" /chronyc-rs -h "$DAEMON_IP" -p 323 "$cmd" \
                >/dev/null 2>&1 || true
            end=$(date +%s%N)
            TIMES+=("$(( (end - start) / 1000000 ))")
        done
        IFS=$'\n' sorted=($(sort -n <<<"${TIMES[*]}")); unset IFS
        mid=$(( ${#sorted[@]} / 2 ))
        LINE="$LINE | ${sorted[$mid]}ms"
    done
    echo "$LINE |" >> "$SUMMARY"
done

docker rm -f "$DAEMON_CID" >/dev/null 2>&1 || true
docker network rm chrony-perf 2>/dev/null || true

# ---- Phase 4: Memory footprint ----
echo "" >> "$SUMMARY"
echo "## 4. Memory Footprint (RSS at idle)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Distro | RSS |" >> "$SUMMARY"
echo "|--------|-----|" >> "$SUMMARY"

for entry in "${DISTROS[@]}"; do
    distro="${entry%%:*}"
    tag="${entry##*:}"
    cid=$(docker run -d --network host \
        -v "$(pwd)/$CHRONYD:/chronyd-rs:ro" \
        -v /tmp/chrony-matrix.conf:/etc/chrony/chrony.conf:ro \
        "$distro:$tag" /chronyd-rs -d -n -f /etc/chrony/chrony.conf 2>/dev/null) || { echo "| $distro | FAIL |" >> "$SUMMARY"; continue; }
    sleep 3
    # Get memory from /proc inside container
    mem=$(docker exec "$cid" cat /proc/self/status 2>/dev/null | grep VmRSS | awk '{print $2 $3}' || echo "?")
    docker rm -f "$cid" >/dev/null 2>&1 || true
    echo "| $distro | $mem |" >> "$SUMMARY"
done

# ---- Phase 5: Build time ----
echo "" >> "$SUMMARY"
echo "## 5. Build Time (incremental, musl release)" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "| Target | Time |" >> "$SUMMARY"
echo "|--------|------|" >> "$SUMMARY"

start=$(date +%s)
cargo build --release --target x86_64-unknown-linux-musl -p chronyd-rs 2>/dev/null
end=$(date +%s)
echo "| chronyd-rs | $(( end - start ))s |" >> "$SUMMARY"

start=$(date +%s)
cargo build --release --target x86_64-unknown-linux-musl -p chronyc-rs 2>/dev/null
end=$(date +%s)
echo "| chronyc-rs | $(( end - start ))s |" >> "$SUMMARY"

echo "" >> "$SUMMARY"
echo "---" >> "$SUMMARY"
echo "*Generated by perf-benchmark.sh*" >> "$SUMMARY"

echo ""
echo "=== Performance benchmark complete ==="
echo "Report: $SUMMARY"
cat "$SUMMARY"
