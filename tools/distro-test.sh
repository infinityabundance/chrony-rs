#!/usr/bin/env bash
# chrony-rs cross-distro integration test
# Tests musl-static chrony-rs binaries on every major Linux distribution.
set -euo pipefail

BIN_DIR="/tmp/chrony-rs-bin"
RESULTS_DIR="/tmp/chrony-rs-distro-results"
CHRONYD="$BIN_DIR/chronyd-rs"
CHRONYC="$BIN_DIR/chronyc-rs"
CONFIG="/tmp/chrony-distro.conf"
mkdir -p "$RESULTS_DIR" "$BIN_DIR"

# Copy binaries
cp target/x86_64-unknown-linux-musl/release/chronyd-rs "$CHRONYD"
cp target/x86_64-unknown-linux-musl/release/chronyc-rs "$CHRONYC"
chmod +x "$CHRONYD" "$CHRONYC"

cat > "$CONFIG" << 'CEOF'
cmdport 323
bindcmdaddress 0.0.0.0
local stratum 10
manual
allow all
cmdallow all
CEOF

DISTROS=(
  "debian:bookworm"
  "ubuntu:noble"
  "fedora:latest"
  "almalinux:9"
  "rockylinux:9"
  "redhat/ubi8"
  "archlinux:latest"
)

run_test() {
  local distro="$1" tag="$2" net="$3" srv_name="$4" cli_name="$5"
  local result_file="$RESULTS_DIR/${distro//\//-}.txt"

  echo "============================================================" | tee -a "$result_file"
  echo " DISTRO: $distro  (tag: $tag)" | tee -a "$result_file"
  echo "============================================================" | tee -a "$result_file"

  # Start server container
  docker rm -f "$srv_name" 2>/dev/null || true
  docker run -d --name "$srv_name" --network "$net" --cap-add=NET_ADMIN --cap-add=SYS_TIME --cap-add=SYS_NICE \
    "$tag" sleep infinity 2>/dev/null

  # Start client container
  docker rm -f "$cli_name" 2>/dev/null || true
  docker run -d --name "$cli_name" --network "$net" \
    "$tag" sleep infinity 2>/dev/null

  # Copy binaries and config
  docker cp "$CHRONYD" "$srv_name:/usr/local/bin/chronyd-rs"
  docker cp "$CHRONYC" "$srv_name:/usr/local/bin/chronyc-rs"
  docker cp "$CHRONYC" "$cli_name:/usr/local/bin/chronyc-rs"
  docker cp "$CONFIG" "$srv_name:/tmp/chrony.conf"

  SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$srv_name")

  # Record OS info
  echo "--- OS RELEASE ---" | tee -a "$result_file"
  docker exec "$srv_name" cat /etc/os-release 2>/dev/null | tee -a "$result_file" || echo "no os-release"
  echo "" | tee -a "$result_file"

  echo "--- BINARY INFO ---" | tee -a "$result_file"
  docker exec "$srv_name" file /usr/local/bin/chronyd-rs 2>/dev/null | tee -a "$result_file"
  docker exec "$srv_name" ldd /usr/local/bin/chronyd-rs 2>&1 | tee -a "$result_file" || echo "ldd failed (static binary - expected)"
  echo "" | tee -a "$result_file"

  # Install necessary tools
  if docker exec "$srv_name" which apt-get 2>/dev/null; then
    docker exec "$srv_name" apt-get update -qq 2>/dev/null && docker exec "$srv_name" apt-get install -y -qq iproute2 strace 2>/dev/null || true
  elif docker exec "$srv_name" which dnf 2>/dev/null; then
    docker exec "$srv_name" dnf install -y -q iproute strace 2>/dev/null || true
  elif docker exec "$srv_name" which yum 2>/dev/null; then
    docker exec "$srv_name" yum install -y -q iproute strace 2>/dev/null || true
  elif docker exec "$srv_name" which pacman 2>/dev/null; then
    docker exec "$srv_name" pacman -Sy --noconfirm iproute2 strace 2>/dev/null || true
  fi

  # Start chronyd-rs
  docker exec -d "$srv_name" /usr/local/bin/chronyd-rs -f /tmp/chrony.conf -d -n 2>&1
  sleep 4

  # Run command suite
  local commands=("tracking" "activity" "n_sources" "serverstats" "sources" "sourcestats")
  local all_ok=true

  for cmd in "${commands[@]}"; do
    echo "--- chronyc $cmd ---" | tee -a "$result_file"
    local output
    output=$(docker exec "$cli_name" /usr/local/bin/chronyc-rs -h "$SERVER_IP" -p 323 "$cmd" 2>&1)
    local exit_code=$?
    echo "$output" | tee -a "$result_file"
    echo "EXIT=$exit_code" | tee -a "$result_file"
    echo "" | tee -a "$result_file"
    if [ "$exit_code" -ne 0 ]; then
      all_ok=false
    fi
    sleep 0.3
  done

  # Check daemon alive
  echo "--- DAEMON STATUS ---" | tee -a "$result_file"
  docker exec "$srv_name" ps aux 2>/dev/null | grep chronyd | grep -v grep | tee -a "$result_file" || echo "DAEMON DEAD" | tee -a "$result_file"
  echo "" | tee -a "$result_file"

  # Check Recv-Q
  echo "--- RECV-Q ---" | tee -a "$result_file"
  docker exec "$srv_name" ss -tulpn 2>/dev/null | grep 323 | tee -a "$result_file" || echo "no ss output" | tee -a "$result_file"

  echo "--- VERDICT: $([ "$all_ok" = true ] && echo 'ALL PASS' || echo 'SOME FAILED') ---" | tee -a "$result_file"
  echo "" | tee -a "$result_file"

  # Cleanup containers
  docker rm -f "$srv_name" "$cli_name" 2>/dev/null || true
}

# Create a single shared network
docker network rm distro-test-net 2>/dev/null || true
docker network create distro-test-net 2>/dev/null

for entry in "${DISTROS[@]}"; do
  local distro="$entry"
  local tag="$entry"
  local srv_name="dt-${distro//\//-}-srv"
  local cli_name="dt-${distro//\//-}-cli"
  
  echo "Pulling $tag..."
  docker pull "$tag" 2>&1 | tail -1
  run_test "$distro" "$tag" "distro-test-net" "$srv_name" "$cli_name"
done

echo ""
echo "============================================================"
echo " ALL DISTRO TESTS COMPLETE"
echo " Results in: $RESULTS_DIR"
echo "============================================================"

# Generate comparison table
echo ""
echo "============================================================"
echo " CROSS-DISTRO COMPARISON"
echo "============================================================"
echo "Distro | Status | Tracking | Activity | Sources | ServerStats | Daemon Persists"
echo "-------|--------|----------|----------|--------|-------------|----------------"

for f in "$RESULTS_DIR"/*.txt; do
  distro=$(basename "$f" .txt)
  status=$(grep "VERDICT:" "$f" | head -1 | sed 's/.*VERDICT: //')
  tracking=$(grep -A1 "chronyc tracking" "$f" | tail -1 | head -c 40)
  daemon=$(grep -c "DAEMON DEAD" "$f" >/dev/null 2>&1 && echo "NO" || echo "YES")
  echo "$distro | $status | $tracking | $daemon"
done
