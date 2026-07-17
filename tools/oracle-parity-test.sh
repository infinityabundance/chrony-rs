#!/usr/bin/env bash
# Ultra-thorough forensic parity audit: chrony-rs vs real chrony 4.5
set -euo pipefail
shopt -s lastpipe

RESULTS="/tmp/chrony-forensic-audit"
rm -rf "$RESULTS" 2>/dev/null; mkdir -p "$RESULTS"

ORACLE_IP="${1:-172.20.0.2}"
CRS_IP="${2:-172.20.0.4}"
ORACLE_PORT=323
CRS_PORT=323

echo "============================================================"
echo " CHRONY-RS vs REAL CHRONY 4.5 — FORENSIC PARITY AUDIT"
echo " $(date)"
echo " Oracle (real chronyd):  $ORACLE_IP"
echo " chrony-rs daemon:       $CRS_IP"
echo "============================================================"

# Step 1: Create identical configs
echo ""
echo "--- Creating identical configs ---"

CONFIG_CONTENT='# Forensic parity test config
cmdport 323
bindcmdaddress 0.0.0.0
local stratum 10
manual
allow all
cmdallow all
logchange 0.0
logdir /tmp/chrony-logs
makestep 1.0 3
maxchange 0.0 0.0 0.0
minsources 1'

docker exec chrony-oracle sh -c "mkdir -p /tmp/chrony-logs; cat > /tmp/chrony-oracle.conf << 'EOF'
$CONFIG_CONTENT
EOF"

docker exec crs-oracle-server sh -c "mkdir -p /tmp/chrony-logs; cat > /tmp/chrony-crs.conf << 'EOF'
$CONFIG_CONTENT
EOF"

echo "Config created (identical for both)"

# Step 2: Kill any existing daemons, start fresh
echo ""
echo "--- Starting daemons ---"

docker exec chrony-oracle pkill chronyd 2>/dev/null || true
docker exec crs-oracle-server pkill chronyd-rs 2>/dev/null || true
sleep 2

# Start real chronyd
docker exec -d chrony-oracle chronyd -f /tmp/chrony-oracle.conf -d -n 2>/dev/null
echo "Real chronyd started"

# Start chrony-rs  
docker exec -d crs-oracle-server /usr/local/bin/chronyd-rs -f /tmp/chrony-crs.conf -d -n 2>/dev/null
echo "chrony-rs started"

sleep 4

echo ""
echo "============================================================"
echo " TEST 1: COMMAND OUTPUT PARITY (identical config, 0 sources)"
echo "============================================================"

run_comparison() {
  local cmd="$1" label="$2" extra_args="${3:-}"
  local oracle_out="$RESULTS/oracle-${label}.txt"
  local crs_out="$RESULTS/crs-${label}.txt"
  local oracle_err="$RESULTS/oracle-${label}-stderr.txt"
  local crs_err="$RESULTS/crs-${label}-stderr.txt"
  
  # Run against oracle
  docker exec chrony-oracle-client chronyc -h "$ORACLE_IP" -p "$ORACLE_PORT" $extra_args $cmd 2>"$oracle_err" > "$oracle_out" || true
  local oec=$?
  
  # Run against chrony-rs
  docker exec crs-oracle-client /usr/local/bin/chronyc-rs -h "$CRS_IP" -p "$CRS_PORT" $extra_args $cmd 2>"$crs_err" > "$crs_out" || true
  local cec=$?
  
  # Compare
  local diff_file="$RESULTS/diff-${label}.txt"
  local identical=true
  
  if ! diff -q "$oracle_out" "$crs_out" >/dev/null 2>&1; then
    identical=false
    diff "$oracle_out" "$crs_out" > "$diff_file" 2>&1 || true
  fi
  
  local oerr=$(cat "$oracle_err" 2>/dev/null | head -3)
  local cerr=$(cat "$crs_err" 2>/dev/null | head -3)
  
  printf "%-30s | exit: %-2d vs %-2d | stdout: %-7s | stderr: %s vs %s\n" \
    "$label" "$oec" "$cec" "$([ "$identical" = true ] && echo 'IDENTICAL' || echo 'DIFFERS')" \
    "${oerr:-(none)}" "${cerr:-(none)}"
  
  if [ "$identical" = false ]; then
    echo "  DIFF file: $diff_file"
    head -20 "$diff_file" 2>/dev/null | sed 's/^/  /'
  fi
}

echo ""
echo "## 1a. Query commands (no sources configured)"

for cmd_spec in \
  "tracking|tracking" \
  "activity|activity" \
  "sources|sources" \
  "sourcestats|sourcestats" \
  "serverstats|serverstats" \
  "n_sources|n_sources" \
  "manual list|manual_list" \
  "smoothing|smoothing" \
  "selectdata|selectdata" \
  "help|help" \
  "version|version"
do
  cmd="${cmd_spec%%|*}"
  label="${cmd_spec##*|}"
  run_comparison "$cmd" "$label"
done

echo ""
echo "## 1b. CSV mode (-c flag)"

for cmd_spec in \
  "tracking|tracking-csv" \
  "activity|activity-csv" \
  "sources|sources-csv" \
  "sourcestats|sourcestats-csv" \
  "serverstats|serverstats-csv" \
  "manual list|manual_list-csv"
do
  cmd="${cmd_spec%%|*}"
  label="${cmd_spec##*|}"
  run_comparison "$cmd" "$label" "-c"
done

echo ""
echo "## 1c. No-DNS mode (-n flag)"

for cmd_spec in \
  "tracking|tracking-nodns" \
  "sources|sources-nodns" \
  "sourcestats|sourcestats-nodns"
do
  cmd="${cmd_spec%%|*}"
  label="${cmd_spec##*|}"
  run_comparison "$cmd" "$label" "-n"
done

echo ""
echo "============================================================"
echo " TEST 2: DAEMON STARTUP OUTPUT PARITY"
echo "============================================================"

echo "## 2a. Startup log lines"
echo "Real chronyd startup:"
docker logs chrony-oracle 2>&1 | head -30
echo ""
echo "chrony-rs startup:"
docker logs crs-oracle-server 2>&1 | head -30
echo ""

echo "## 2b. Listening ports"
echo "Real chronyd:"
docker exec chrony-oracle ss -tulpn 2>/dev/null | grep chrony
echo ""
echo "chrony-rs:"
docker exec crs-oracle-server ss -tulpn 2>/dev/null | grep chronyd-rs

echo ""
echo "## 2c. Running processes"
echo "Real chronyd:"
docker exec chrony-oracle ps aux | grep chrony
echo ""
echo "chrony-rs:"
docker exec crs-oracle-server ps aux | grep chronyd-rs

echo ""
echo "============================================================"
echo " TEST 3: ERROR HANDLING PARITY"
echo "============================================================"

echo "## 3a. No daemon running"
docker exec chrony-oracle pkill chronyd 2>/dev/null || true
docker exec crs-oracle-server pkill chronyd-rs 2>/dev/null || true
sleep 2

run_comparison "tracking" "err-no-daemon-oracle" "" chrony-oracle-client
run_comparison "tracking" "err-no-daemon-crs" "" crs-oracle-client

echo "## 3b. Wrong port"
ORACLE_PORT_SAVE=$ORACLE_PORT
CRS_PORT_SAVE=$CRS_PORT
ORACLE_PORT=324
CRS_PORT=324
run_comparison "tracking" "err-wrong-port"
ORACLE_PORT=$ORACLE_PORT_SAVE
CRS_PORT=$CRS_PORT_SAVE

echo "## 3c. Invalid command"
run_comparison "nonexistent" "err-bad-command"

echo "## 3d. Version mismatch (future version)"
run_comparison "tracking" "err-version" "-v 7"

echo ""
echo "============================================================"
echo " TEST 4: CONFIG PARSING PARITY"
echo "============================================================"

echo "## 4a. Print parsed config (-p)"
echo "Real chronyd -p:"
docker exec chrony-oracle chronyd -f /tmp/chrony-oracle.conf -p 2>&1 | head -20
echo ""
echo "chrony-rs -p:"
docker exec crs-oracle-server /usr/local/bin/chronyd-rs -f /tmp/chrony-crs.conf -p 2>&1 | head -20

echo ""
echo "============================================================"
echo " TEST 5: BINARY PROPERTIES"
echo "============================================================"

echo "## 5a. Binary sizes"
echo "Real chronyd:"
docker exec chrony-oracle file "$(which chronyd)" 2>/dev/null || docker exec chrony-oracle file /usr/sbin/chronyd 2>/dev/null
docker exec chrony-oracle du -h "$(which chronyd 2>/dev/null || echo /usr/sbin/chronyd)" 2>/dev/null
echo ""
echo "chrony-rs:"
docker exec crs-oracle-server file /usr/local/bin/chronyd-rs 2>/dev/null
docker exec crs-oracle-server du -h /usr/local/bin/chronyd-rs 2>/dev/null
echo ""
echo "Real chronyc:"
docker exec chrony-oracle-client file "$(which chronyc 2>/dev/null || echo /usr/bin/chronyc)" 2>/dev/null
docker exec chrony-oracle-client du -h "$(which chronyc 2>/dev/null || echo /usr/bin/chronyc)" 2>/dev/null
echo ""
echo "chronyc-rs:"
docker exec crs-oracle-client file /usr/local/bin/chronyc-rs 2>/dev/null
docker exec crs-oracle-client du -h /usr/local/bin/chronyc-rs 2>/dev/null

echo ""
echo "============================================================"
echo " TEST 6: NETWORK PROTOCOL COMPATIBILITY"
echo "============================================================"

# Restart both daemons  
docker exec -d chrony-oracle chronyd -f /tmp/chrony-oracle.conf -d -n 2>/dev/null
docker exec -d crs-oracle-server /usr/local/bin/chronyd-rs -f /tmp/chrony-crs.conf -d -n 2>/dev/null
sleep 5

echo "## 6a. Real chronyc → chrony-rs daemon"
echo "(testing if real chronyc can talk to chrony-rs daemon)"
docker exec chrony-oracle-client chronyc -h "$CRS_IP" -p "$CRS_PORT" tracking 2>&1
echo "exit=$?"

echo ""
echo "## 6b. chronyc-rs → real chronyd daemon"
echo "(testing if chronyc-rs can talk to real chronyd)"
docker exec crs-oracle-client /usr/local/bin/chronyc-rs -h "$ORACLE_IP" -p "$ORACLE_PORT" tracking 2>&1
echo "exit=$?"

echo ""
echo "============================================================"
echo " TEST 7: ACTION COMMANDS (if supported)"
echo "============================================================"

echo "## 7a. chronyc-rs shutdown (remote daemon)"
echo "(testing shutdown command on chrony-rs daemon)"
docker exec crs-oracle-client /usr/local/bin/chronyc-rs -h "$CRS_IP" -p "$CRS_PORT" shutdown 2>&1
echo "exit=$?"
sleep 2
echo "Daemon alive after shutdown?"
docker exec crs-oracle-server ps aux 2>/dev/null | grep chronyd | grep -v grep | head -2 || echo "Daemon DEAD (expected)"

echo ""
echo "## 7b. chronyc shutdown (real chronyd)"
echo "(testing shutdown command on real chronyd)"
docker exec chrony-oracle-client chronyc -h "$ORACLE_IP" -p "$ORACLE_PORT" shutdown 2>&1
echo "exit=$?"
sleep 2
echo "Daemon alive after shutdown?"
docker exec chrony-oracle ps aux 2>/dev/null | grep chrony | grep -v grep | head -2 || echo "Daemon DEAD (expected)"

echo ""
echo "============================================================"
echo " TEST 8: COMPREHENSIVE DIFF SUMMARY"
echo "============================================================"

echo ""
echo "## 8a. All differences found:"
diff_count=0
for f in "$RESULTS"/diff-*.txt; do
  if [ -f "$f" ] && [ -s "$f" ]; then
    diff_count=$((diff_count + 1))
    echo "  [$diff_count] $(basename "$f" .txt | sed 's/^diff-//')"
    cat "$f" | head -30 | sed 's/^/    /'
    echo ""
  fi
done

if [ "$diff_count" -eq 0 ]; then
  echo "  (none — all outputs byte-identical!)"
fi

echo ""
echo "## 8b. Summary: commands with output differences"
echo "Command                    | Oracle Real chrony | chrony-rs | Match?"
echo "---------------------------|-------------------|-----------|-------"
for f in "$RESULTS"/oracle-*.txt; do
  base=$(basename "$f" .txt | sed 's/^oracle-//')
  crs="$RESULTS/crs-${base}.txt"
  diff_f="$RESULTS/diff-${base}.txt"
  if [ -f "$crs" ]; then
    if [ -f "$diff_f" ] && [ -s "$diff_f" ]; then
      match="❌ DIFFERS"
    else
      match="✅ MATCH"
    fi
  else
    match="⚠️ NO CRS OUTPUT"
  fi
  printf "%-27s | %-17s | %-9s | %s\n" "$base" "chrony 4.5" "chrony-rs" "$match"
done

echo ""
echo "============================================================"
echo " COMPREHENSIVE SUMMARY"
echo "============================================================"

echo ""
echo "Total test categories: 8"
echo "  Test 1: Command output parity (${diff_count:-0} differences)"
echo "  Test 2: Daemon startup parity"
echo "  Test 3: Error handling parity"
echo "  Test 4: Config parsing parity"
echo "  Test 5: Binary properties"
echo "  Test 6: Cross-compatibility"
echo "  Test 7: Action commands"
echo "  Test 8: Diff summary"
echo ""
echo "Full results in: $RESULTS"
