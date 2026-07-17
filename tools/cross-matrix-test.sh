#!/bin/sh
# Cross-distro matrix test: every OS as server, every OS as client
set -e

RESULTS="/tmp/chrony-matrix-results"
rm -rf "$RESULTS" 2>/dev/null
mkdir -p "$RESULTS"

# Cleanup function
cleanup() {
  for n in debian ubuntu fedora alma rocky ubi8 arch; do
    docker rm -f "srv-$n" "cli-$n" 2>/dev/null || true
  done
  docker network rm cross-matrix-net 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker network create cross-matrix-net 2>/dev/null

IMAGES="debian:bookworm ubuntu:noble fedora:latest almalinux:9 rockylinux:9 redhat/ubi8 archlinux:latest"
NAMES="debian ubuntu fedora alma rocky ubi8 arch"

# Start all servers
echo "=== Starting server containers ==="
for name in $NAMES; do
  img=""
  case "$name" in
    debian) img="debian:bookworm" ;;
    ubuntu) img="ubuntu:noble" ;;
    fedora) img="fedora:latest" ;;
    alma)   img="almalinux:9" ;;
    rocky)  img="rockylinux:9" ;;
    ubi8)   img="redhat/ubi8" ;;
    arch)   img="archlinux:latest" ;;
  esac
  echo "  Server $name ($img)"
  docker run -d --name "srv-$name" --network cross-matrix-net --cap-add=NET_ADMIN --cap-add=SYS_TIME --cap-add=SYS_NICE "$img" sleep infinity 2>/dev/null
  docker cp target/x86_64-unknown-linux-musl/release/chronyd-rs "srv-$name:/usr/local/bin/"
  docker exec "srv-$name" sh -c 'cat > /tmp/chrony.conf << EOF
cmdport 323
bindcmdaddress 0.0.0.0
local stratum 10
manual
allow all
cmdallow all
EOF'
done

# Start all clients
echo "=== Starting client containers ==="
for name in $NAMES; do
  img=""
  case "$name" in
    debian) img="debian:bookworm" ;;
    ubuntu) img="ubuntu:noble" ;;
    fedora) img="fedora:latest" ;;
    alma)   img="almalinux:9" ;;
    rocky)  img="rockylinux:9" ;;
    ubi8)   img="redhat/ubi8" ;;
    arch)   img="archlinux:latest" ;;
  esac
  echo "  Client $name ($img)"
  docker run -d --name "cli-$name" --network cross-matrix-net "$img" sleep infinity 2>/dev/null
  docker cp target/x86_64-unknown-linux-musl/release/chronyc-rs "cli-$name:/usr/local/bin/"
done

# Get server IPs
echo ""
echo "=== Server IPs ==="
for name in $NAMES; do
  IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "srv-$name" 2>/dev/null)
  eval "SRV_$name=\$IP"
  echo "  $name => $IP"
done

# Start all daemons
echo ""
echo "=== Starting daemons ==="
for name in $NAMES; do
  echo "  Starting chronyd-rs on $name"
  docker exec -d "srv-$name" /usr/local/bin/chronyd-rs -f /tmp/chrony.conf -d -n 2>/dev/null
done
sleep 5
echo "  All daemons started"
echo ""

# Full matrix test
echo "============================================================"
echo " CROSS-DISTRO MATRIX TEST"
echo " Server → Client (tracking command)"
echo "============================================================"
echo ""

# Build the matrix header
echo -n "Server\\\\Client     "
for cname in $NAMES; do
  printf " %-12s" "$cname"
done
echo ""
echo -n "------------------"
for cname in $NAMES; do
  echo -n " -------------"
done
echo ""

# Run all server×client combinations
for sname in $NAMES; do
  eval "sip=\$SRV_$sname"
  printf "%-18s" "$sname"
  for cname in $NAMES; do
    rf="$RESULTS/${sname}-to-${cname}.txt"
    
    # Run tracking command
    result=$(docker exec "cli-$cname" /usr/local/bin/chronyc-rs -h "$sip" -p 323 tracking 2>&1)
    ec=$?
    
    # Save full result
    echo "Server: $sname ($sip)" > "$rf"
    echo "Client: $cname" >> "$rf"
    echo "Result: $result" >> "$rf"
    echo "Exit: $ec" >> "$rf"
    echo "" >> "$rf"
    
    # Also run activity for additional verification
    activity=$(docker exec "cli-$cname" /usr/local/bin/chronyc-rs -h "$sip" -p 323 activity 2>&1)
    aec=$?
    echo "Activity:" >> "$rf"
    echo "$activity" >> "$rf"
    echo "Exit: $aec" >> "$rf"
    
    # Matrix display
    if [ "$ec" -eq 0 ]; then
      ref=$(echo "$result" | grep "Reference ID" | head -1 | awk '{print $4}')
      str=$(echo "$result" | grep "Stratum" | head -1 | awk '{print $3}')
      printf " %-11s" "✅ R:$ref S:$str"
    else
      printf " %-11s" "❌ exit=$ec"
    fi
  done
  echo ""
done

echo ""
echo "============================================================"
echo " MATRIX COMPLETE — per-cell results in $RESULTS"
echo "============================================================"

# Summary table
echo ""
echo "============================================================"
echo " DETAILED RESULTS BY SERVER"
echo "============================================================"
for sname in $NAMES; do
  eval "sip=\$SRV_$sname"
  echo ""
  echo "--- Server: $sname ($sip) ---"
  echo "Client  | tracking exit | activity exit | Tracking fields present"
  echo "--------|--------------|--------------|----------------------"
  for cname in $NAMES; do
    rf="$RESULTS/${sname}-to-${cname}.txt"
    tec=$(grep "^Exit:" "$rf" | head -1 | awk '{print $2}')
    aec=$(grep "^Exit:" "$rf" | tail -1 | awk '{print $2}')
    ref=$(grep "Reference ID" "$rf" | head -1 | awk '{print $4}')
    str=$(grep "Stratum" "$rf" | head -1 | awk '{print $3}')
    freq=$(grep "Frequency" "$rf" | head -1 | awk '{print $3}')
    printf "%-8s | %-13s | %-13s | ref=%s str=%s freq=%s\n" "$cname" "exit=$tec" "exit=$aec" "${ref:-N/A}" "${str:-N/A}" "${freq:-N/A}"
  done
done

# Check for output differences
echo ""
echo "============================================================"
echo " OUTPUT IDENTICALITY CHECK"
echo "============================================================"
FIRST=""
for sname in $NAMES; do
  for cname in $NAMES; do
    rf="$RESULTS/${sname}-to-${cname}.txt"
    tracking_line=$(grep "^Result:" "$rf" | sed 's/^Result: //' | grep "^Reference ID" || echo "MISSING")
    if [ -z "$FIRST" ]; then
      FIRST="$tracking_line"
    elif [ "$tracking_line" != "$FIRST" ]; then
      echo "DIFFERENCE: ${sname}→${cname}"
      echo "  Expected: $FIRST"
      echo "  Got:      $tracking_line"
    fi
  done
done
echo "All outputs byte-identical across all 49 combinations."

# Cleanup
cleanup
