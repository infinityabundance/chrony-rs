#!/bin/sh
# Quick chrony version matrix test
set -e
RESULTS="/home/one/chrony-rs/research/version-matrix"
rm -rf "$RESULTS" 2>/dev/null
mkdir -p "$RESULTS"

# Test chrony-rs daemon vs chronyc from different chrony versions
# chrony 4.5 from ubuntu:noble
echo "=== Testing chronyc 4.5 against chrony-rs ==="
docker rm -f vm 2>/dev/null
docker run -d --name vm --network host --cap-add=NET_ADMIN --cap-add=SYS_TIME ubuntu:noble sleep infinity 2>/dev/null
docker exec vm apt-get update -qq 2>&1 | tail -1
docker exec vm apt-get install -y -qq chrony 2>&1 | tail -3
docker cp /home/one/chrony-rs/target/x86_64-unknown-linux-musl/release/chronyd-rs vm:/usr/local/bin/
docker exec vm sh -c 'cat > /tmp/c.conf << EOF
cmdport 323
bindcmdaddress 0.0.0.0
local stratum 10
manual
allow all
cmdallow all
EOF'
docker exec vm pkill chronyd 2>/dev/null || true; sleep 2
docker exec -d vm /usr/local/bin/chronyd-rs -f /tmp/c.conf -d -n 2>/dev/null; sleep 5

VERSION=$(docker exec vm chronyc --version 2>/dev/null | head -1)
echo "chronyc version: $VERSION"

# Capture all outputs
for cmd in tracking activity n_sources sources sourcestats serverstats rtcdata smoothing selectdata; do
  docker exec vm chronyc -h 127.0.0.1 -p 323 $cmd > "$RESULTS/${cmd}-v45.txt" 2>/dev/null
  docker exec vm chronyc -c -h 127.0.0.1 -p 323 $cmd > "$RESULTS/${cmd}-v45-csv.txt" 2>/dev/null || true
done
docker exec vm chronyc -h 127.0.0.1 -p 323 tracking > "$RESULTS/tracking-v45.txt" 2>/dev/null

echo "Done with chrony 4.5"

# Now test against chrony-rs client to compare outputs
docker exec vm /usr/local/bin/chronyc-rs -h 127.0.0.1 -p 323 tracking > "$RESULTS/tracking-crs.txt" 2>/dev/null

echo "=== Cross-version diff ==="
echo "Comparing chronyc 4.5 vs chronyc-rs tracking:"
diff -u "$RESULTS/tracking-v45.txt" "$RESULTS/tracking-crs.txt" || true

docker rm -f vm 2>/dev/null
echo "=== Complete ==="
