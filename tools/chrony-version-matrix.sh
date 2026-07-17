#!/bin/bash
# chrony-version-matrix.sh
#
# Version-matrix test: chronyd-rs × real chronyc clients (4.2 / 4.3 / 4.4 / 4.5).
#
# For each chrony version, we:
#   1. Start a Docker container with chrony from apt (or built from source for 4.4)
#   2. Deploy the chronyd-rs binary into the container
#   3. Start chronyd-rs as the daemon
#   4. Run the real chronyc against localhost for 8 report commands
#   5. Capture byte-exact output
#   6. Compare outputs across versions and generate a diff report
#
# The versions are mapped as follows:
#   chrony 4.2  ← Ubuntu 22.04 (jammy)   — apt install
#   chrony 4.3  ← Ubuntu 23.10 (mantic)  — apt install (old-releases)
#   chrony 4.4  ← Source build           — compiled from chrony-project.org tarball
#   chrony 4.5  ← Ubuntu 24.04 (noble)   — apt install
#
# Usage:  ./tools/chrony-version-matrix.sh
#
# Prerequisites:
#   - docker
#   - chronyd-rs and chronyc-rs already built
#     (or run with CARGO_BUILD=1 to build automatically)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- Configuration --------------------------------------------------------
RESULTS="$PROJECT_ROOT/research/version-matrix"
CHRONYD_BIN="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/chronyd-rs"
CHRONYC_BIN="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/chronyc-rs"
CARGO_BUILD="${CARGO_BUILD:-0}"

# The 8 report commands we test
COMMANDS=(
  "tracking"
  "activity"
  "sources"
  "sourcestats"
  "serverstats"
  "rtcdata"
  "smoothing"
  "selectdata"
)

# Version matrix: (label, ubuntu_version, chrony_apt_version, install_method)
# install_method: "apt" or "source"
# For "apt": the image is ubuntu:<ubuntu_version>, chrony installed from repos
# For "source": chrony compiled from upstream tarball

# ---- Helper: find actual chrony version in an Ubuntu image ----------------
detect_apt_version() {
  local ubuntu_ver="$1"
  local sources_list_fix="$2"  # "old" if using old-releases, empty otherwise

  local fix_cmd=""
  if [ "$sources_list_fix" = "old" ]; then
    fix_cmd='sed -i "s/archive.ubuntu.com/old-releases.ubuntu.com/g; s/security.ubuntu.com/old-releases.ubuntu.com/g" /etc/apt/sources.list 2>/dev/null; sed -i "s/security.ubuntu.com/old-releases.ubuntu.com/g" /etc/apt/sources.list.d/*.sources 2>/dev/null || true;'
  fi

  docker run --rm "ubuntu:${ubuntu_ver}" sh -c "
    ${fix_cmd}
    apt-get update -qq 2>/dev/null
    apt-cache show chrony 2>/dev/null | grep ^Version | head -1 | awk '{print \$2}'
  " 2>/dev/null || echo "unknown"
}

VERSIONS=()

# ---- Discover available versions ------------------------------------------
echo "=== Discovering chrony versions ==="

# 4.2 — Ubuntu 22.04 (jammy)
v42=$(detect_apt_version "22.04" "")
if [ -n "$v42" ]; then
  echo "  Ubuntu 22.04 → chrony $v42"
  VERSIONS+=("4.2:22.04:apt:")
fi

# 4.3 — Ubuntu 23.10 (mantic) [EOL, needs old-releases]
v43=$(detect_apt_version "23.10" "old")
if [ -n "$v43" ]; then
  echo "  Ubuntu 23.10 → chrony $v43"
  VERSIONS+=("4.3:23.10:apt:old")
fi

# 4.4 — Build from source tarball (not packaged in any Ubuntu release)
echo "  chrony 4.4 → source build from chrony-project.org"
VERSIONS+=("4.4:source:source:")

# 4.5 — Ubuntu 24.04 (noble)
v45=$(detect_apt_version "24.04" "")
if [ -n "$v45" ]; then
  echo "  Ubuntu 24.04 → chrony $v45"
  VERSIONS+=("4.5:24.04:apt:")
fi

echo "  → $(echo "${VERSIONS[@]}" | wc -w) version(s) to test"
echo ""

# ---- Build Rust binaries if requested -------------------------------------
if [ "$CARGO_BUILD" = "1" ]; then
  echo "=== Building chrony-rs ==="
  (cd "$PROJECT_ROOT" && cargo build --release --target x86_64-unknown-linux-musl -p chronyd-rs -p chronyc-rs)
  echo ""
fi

if [ ! -x "$CHRONYD_BIN" ] || [ ! -x "$CHRONYC_BIN" ]; then
  echo "ERROR: chronyd-rs and/or chronyc-rs binaries not found."
  echo "  Expected: $CHRONYD_BIN"
  echo "  Expected: $CHRONYC_BIN"
  echo "  Build with: cargo build --release --target x86_64-unknown-linux-musl -p chronyd-rs -p chronyc-rs"
  echo "  Or set CARGO_BUILD=1 to build automatically."
  exit 1
fi

# ---- Cleanup and setup ----------------------------------------------------
rm -rf "$RESULTS"
mkdir -p "$RESULTS"

CLEANUP_CONTAINERS=()

cleanup() {
  local ec=$?
  echo ""
  echo "=== Cleaning up ==="
  for cid in "${CLEANUP_CONTAINERS[@]}"; do
    docker rm -f "$cid" 2>/dev/null || true
  done
  docker network rm chrony-version-net 2>/dev/null || true
  exit $ec
}
trap cleanup EXIT

docker network create chrony-version-net 2>/dev/null || true
cleanup  # clean any leftovers from previous interrupted runs

# ---- For each version ---------------------------------------------------
# Summary JSON is written after all versions finish processing
JSON_ENTRIES=""

for version_spec in "${VERSIONS[@]}"; do
  IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"

  echo ""
  echo "============================================================"
  echo "  chrony $label"
  echo "============================================================"

  VER_DIR="$RESULTS/$label"
  mkdir -p "$VER_DIR"

  # Create a container for this version
  CONTAINER_NAME="chrony-matrix-${label}"
  CLEANUP_CONTAINERS+=("$CONTAINER_NAME")
  docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

  # ---- Start container ---------------------------------------------------
  echo "  Starting container: ubuntu:${ubuntu_ver}"

  if [ "$method" = "source" ]; then
    # For source build (4.4): start with ubuntu:22.04 (stable base)
    docker run -d --name "$CONTAINER_NAME" \
      --network chrony-version-net \
      --cap-add=NET_ADMIN --cap-add=SYS_TIME --cap-add=SYS_NICE \
      ubuntu:22.04 sleep infinity >/dev/null
  else
    docker run -d --name "$CONTAINER_NAME" \
      --network chrony-version-net \
      --cap-add=NET_ADMIN --cap-add=SYS_TIME --cap-add=SYS_NICE \
      "ubuntu:${ubuntu_ver}" sleep infinity >/dev/null
  fi

  # ---- Install build deps & chrony ---------------------------------------
  echo "  Installing chrony (version $label)..."

  if [ "$method" = "apt" ]; then
    # Install from apt
    fix_cmd=""
    if [ "$sources_fix" = "old" ]; then
      fix_cmd='sed -i "s/archive.ubuntu.com/old-releases.ubuntu.com/g; s/security.ubuntu.com/old-releases.ubuntu.com/g" /etc/apt/sources.list; sed -i "s/security.ubuntu.com/old-releases.ubuntu.com/g" /etc/apt/sources.list.d/*.sources 2>/dev/null || true;'
    fi
    docker exec "$CONTAINER_NAME" sh -c "
      ${fix_cmd}
      apt-get update -qq 2>/dev/null
      apt-get install -y -qq chrony 2>/dev/null
    " >/dev/null
  else
    # Build from source (chrony 4.4)
    docker exec "$CONTAINER_NAME" sh -c "
      apt-get update -qq 2>/dev/null
      apt-get install -y -qq build-essential curl libcap-dev libnss3-dev libseccomp-dev \
        pkg-config nettle-dev gnutls-bin 2>/dev/null
      cd /tmp
      curl -sSLO https://chrony-project.org/releases/chrony-4.4.tar.gz
      tar xzf chrony-4.4.tar.gz
      cd chrony-4.4
      ./configure --prefix=/usr --sysconfdir=/etc/chrony 2>/dev/null
      make -j\$(nproc) 2>/dev/null
      make install 2>/dev/null
    " >/dev/null
  fi

  # Verify chronyc is installed
  CHRONYC_REAL=$(docker exec "$CONTAINER_NAME" which chronyc 2>/dev/null || true)
  if [ -z "$CHRONYC_REAL" ]; then
    echo "  ERROR: chronyc not found after installation. Skipping $label."
    continue
  fi
  CHRONYC_VER=$(docker exec "$CONTAINER_NAME" chronyc -v 2>&1 | head -1 || echo "unknown")
  echo "  chronyc binary: $CHRONYC_REAL ($CHRONYC_VER)"

  # ---- Deploy chronyd-rs -------------------------------------------------
  echo "  Deploying chronyd-rs..."
  docker cp "$CHRONYD_BIN" "$CONTAINER_NAME:/usr/local/bin/chronyd-rs"

  # Create chrony config for chronyd-rs
  docker exec "$CONTAINER_NAME" sh -c 'cat > /tmp/chrony-matrix.conf << EOF
cmdport 323
bindcmdaddress 0.0.0.0
local stratum 10
manual
allow all
cmdallow all
EOF'

  # ---- Start chronyd-rs daemon -------------------------------------------
  echo "  Starting chronyd-rs daemon..."
  docker exec -d "$CONTAINER_NAME" /usr/local/bin/chronyd-rs -f /tmp/chrony-matrix.conf -d -n 2>/dev/null
  sleep 3

  # Verify daemon is running
  if ! docker exec "$CONTAINER_NAME" sh -c 'kill -0 $(pidof chronyd-rs) 2>/dev/null' 2>/dev/null; then
    echo "  ERROR: chronyd-rs failed to start. Logs:"
    docker exec "$CONTAINER_NAME" sh -c 'pidof chronyd-rs' 2>/dev/null || echo "    (not running)"
    continue
  fi
  echo "  chronyd-rs daemon running."

  # Verify we can reach the command port
  if ! docker exec "$CONTAINER_NAME" chronyc -h 127.0.0.1 -p 323 tracking >/dev/null 2>&1; then
    echo "  WARNING: chronyd-rs not responding on cmd port. Retrying after short wait..."
    sleep 5
    if ! docker exec "$CONTAINER_NAME" chronyc -h 127.0.0.1 -p 323 tracking >/dev/null 2>&1; then
      echo "  ERROR: chronyd-rs still not responding after retry."
    fi
  fi

  # ---- Run the 8 report commands -----------------------------------------
  echo "  Running report commands..."

  for cmd in "${COMMANDS[@]}"; do
    echo "    chronyc $cmd"

    # Determine if the command supports -v flag
    extra_flags=""
    case "$cmd" in
      sources|sourcestats|selectdata|ntpdata)
        extra_flags="-v"
        ;;
    esac

    # Capture byte-exact output
    out_file="$VER_DIR/${cmd}.txt"
    {
      echo "# chronyc $cmd"
      echo "# chrony version: $CHRONYC_VER"
      echo "# chrony label: $label"
      echo ""
    } > "$out_file"

    # Run the real chronyc
    docker exec "$CONTAINER_NAME" \
      chronyc -h 127.0.0.1 -p 323 $cmd $extra_flags \
      2>&1 >> "$out_file" || true

    # Also chronyc -c (csv) if the command supports it
    csv_file="$VER_DIR/${cmd}-csv.txt"
    {
      echo "# chronyc -c $cmd"
      echo "# chrony version: $CHRONYC_VER"
      echo "# chrony label: $label"
      echo ""
    } > "$csv_file"

    docker exec "$CONTAINER_NAME" \
      chronyc -c -h 127.0.0.1 -p 323 $cmd \
      2>&1 >> "$csv_file" || true
  done

  # ---- Record version info -----------------------------------------------
  ver_file="$VER_DIR/version.txt"
  {
    echo "chrony version: $CHRONYC_VER"
    echo "chrony label: $label"
    docker exec "$CONTAINER_NAME" chronyc -v 2>&1
    echo ""
    echo "--- system info ---"
    docker exec "$CONTAINER_NAME" cat /etc/os-release 2>/dev/null | head -10
    docker exec "$CONTAINER_NAME" uname -r -m 2>/dev/null
  } > "$ver_file"

  # ---- Accumulate JSON entry ------------------------------------------
  escaped_ver=$(echo "$CHRONYC_VER" | sed 's/"/\\"/g')
  json_entry="\"$label\": {\"version\": \"$escaped_ver\", \"ubuntu\": \"$ubuntu_ver\", \"method\": \"$method\"}"
  if [ -z "$JSON_ENTRIES" ]; then
    JSON_ENTRIES="$json_entry"
  else
    JSON_ENTRIES="$JSON_ENTRIES, $json_entry"
  fi

  echo "  Output saved to $VER_DIR/"
  echo "  Done with chrony $label"
done

# Write summary JSON
RESULTS_FILE="$RESULTS/summary.json"
{
  echo "{"
  echo "  \"versions\": {"
  echo "    $JSON_ENTRIES"
  echo "  }"
  echo "}"
} > "$RESULTS_FILE"

# ---- Cross-version diff report -------------------------------------------
echo ""
echo "============================================================"
echo "  CROSS-VERSION DIFF REPORT"
echo "============================================================"

if [ "${#VERSIONS[@]}" -lt 2 ]; then
  echo "  (Fewer than 2 versions tested; no diff possible.)"
  echo ""
  echo "============================================================"
  echo "  RESULTS: $RESULTS/"
  echo "============================================================"
  exit 0
fi

echo ""

# Use the first version as baseline
BASELINE="${VERSIONS[0]%%:*}"
DIFF_REPORT="$RESULTS/cross-version-diff.txt"

{
  echo "============================================================"
  echo " chrony-rs × real chronyc — Version Matrix Diff Report"
  echo " Generated: $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "============================================================"
  echo ""
  echo "Baseline: chrony $BASELINE"
  echo "Compared:"

  for version_spec in "${VERSIONS[@]}"; do
    IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
    if [ "$label" != "$BASELINE" ]; then
      echo "  - chrony $label"
    fi
  done

  echo ""
  echo "---"
  echo ""
} > "$DIFF_REPORT"

ANY_DIFF=false

for cmd in "${COMMANDS[@]}"; do
  BASELINE_FILE="$RESULTS/$BASELINE/${cmd}.txt"

  if [ ! -f "$BASELINE_FILE" ]; then
    echo "  WARNING: Baseline file missing: $BASELINE_FILE" >> "$DIFF_REPORT"
    continue
  fi

  # Strip header lines (starting with #) for content comparison
  BASELINE_CONTENT=$(sed '/^#/d' "$BASELINE_FILE")

  for version_spec in "${VERSIONS[@]}"; do
    IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
    [ "$label" = "$BASELINE" ] && continue

    COMPARE_FILE="$RESULTS/$label/${cmd}.txt"

    if [ ! -f "$COMPARE_FILE" ]; then
      echo "  WARNING: File missing for $label/$cmd" >> "$DIFF_REPORT"
      continue
    fi

    COMPARE_CONTENT=$(sed '/^#/d' "$COMPARE_FILE")

    if [ "$BASELINE_CONTENT" != "$COMPARE_CONTENT" ]; then
      ANY_DIFF=true
      {
        echo ""
        echo "============================================================"
        echo " DIFF: chrony $BASELINE vs chrony $label  —  chronyc $cmd"
        echo "============================================================"
        echo ""
        diff -u \
          <(echo "$BASELINE_CONTENT") \
          <(echo "$COMPARE_CONTENT") \
          || true
        echo ""
      } >> "$DIFF_REPORT"
    fi
  done
done

# Also diff CSV output
for cmd in "${COMMANDS[@]}"; do
  BASELINE_CSV="$RESULTS/$BASELINE/${cmd}-csv.txt"

  if [ ! -f "$BASELINE_CSV" ]; then
    continue
  fi

  BASELINE_CSV_CONTENT=$(sed '/^#/d' "$BASELINE_CSV")

  for version_spec in "${VERSIONS[@]}"; do
    IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
    [ "$label" = "$BASELINE" ] && continue

    COMPARE_CSV="$RESULTS/$label/${cmd}-csv.txt"

    if [ ! -f "$COMPARE_CSV" ]; then
      continue
    fi

    COMPARE_CSV_CONTENT=$(sed '/^#/d' "$COMPARE_CSV")

    if [ "$BASELINE_CSV_CONTENT" != "$COMPARE_CSV_CONTENT" ]; then
      ANY_DIFF=true
      {
        echo ""
        echo "============================================================"
        echo " DIFF (CSV): chrony $BASELINE vs chrony $label  —  chronyc -c $cmd"
        echo "============================================================"
        echo ""
        diff -u \
          <(echo "$BASELINE_CSV_CONTENT") \
          <(echo "$COMPARE_CSV_CONTENT") \
          || true
        echo ""
      } >> "$DIFF_REPORT"
    fi
  done
done

# ---- Summary ------------------------------------------------------------
{
  echo ""
  echo "============================================================"
  echo " SUMMARY"
  echo "============================================================"
  echo ""
  echo "Versions tested: ${#VERSIONS[@]}"
  for version_spec in "${VERSIONS[@]}"; do
    IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
    echo "  chrony $label (ubuntu:$ubuntu_ver, method=$method)"
  done
  echo ""
  echo "Commands tested: ${#COMMANDS[@]}"
  for cmd in "${COMMANDS[@]}"; do printf "  - %s\n" "$cmd"; done
  echo ""
  echo "Byte-identical outputs across all versions:"
  if [ "$ANY_DIFF" = true ]; then
    echo "  ❌ Differences found (see diff report)"
  else
    echo "  ✅ All outputs byte-identical across all versions!"
  fi
  echo ""
  echo "Results directory: $RESULTS/"
  echo "Diff report:       $DIFF_REPORT"
  echo "============================================================"
} >> "$DIFF_REPORT"

# Print summary to stdout if no differences
if [ "$ANY_DIFF" = false ]; then
  echo ""
  echo "============================================================"
  echo "  ✅ All outputs byte-identical across all versions!"
  echo "============================================================"
fi

echo ""
echo "Results: $RESULTS/"
echo "Diff report: $DIFF_REPORT"

# ---- Per-version output comparison table ---------------------------------
echo ""
echo "=== Per-version output sizes ==="
printf "%-12s" "Command"
for version_spec in "${VERSIONS[@]}"; do
  IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
  printf " %-18s" "$label"
done
echo ""
printf "%-12s" "--------"
for version_spec in "${VERSIONS[@]}"; do
  printf " %-18s" "------------------"
done
echo ""

for cmd in "${COMMANDS[@]}"; do
  printf "%-12s" "$cmd"
  for version_spec in "${VERSIONS[@]}"; do
    IFS=':' read -r label ubuntu_ver method sources_fix <<< "$version_spec"
    f="$RESULTS/$label/${cmd}.txt"
    if [ -f "$f" ]; then
      sz=$(wc -c < "$f")
      lines=$(wc -l < "$f")
      # Check if content matches baseline
      if [ "$label" = "$BASELINE" ]; then
        printf " %5db %3dl   *" "$sz" "$lines"
      else
        bf="$RESULTS/$BASELINE/${cmd}.txt"
        if [ -f "$bf" ]; then
          bcont=$(sed '/^#/d' "$bf")
          ccont=$(sed '/^#/d' "$f")
          if [ "$bcont" = "$ccont" ]; then
            printf " %5db %3dl  ✅" "$sz" "$lines"
          else
            printf " %5db %3dl  ❌" "$sz" "$lines"
          fi
        else
          printf " %5db %3dl  ?" "$sz" "$lines"
        fi
      fi
    else
      printf " %-18s" "  (missing)"
    fi
  done
  echo ""
done

echo ""
echo "=== Legend ==="
echo "  *  = baseline"
echo "  ✅ = output identical to baseline"
echo "  ❌ = output differs from baseline"
echo ""
echo "Done."
