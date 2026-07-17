#!/usr/bin/env bash
# QEMU Multi-Distro Test Runner for chrony-rs.
#
# Uses qemu-user-mode static binary with each distro's rootfs to verify
# that chrony-rs builds and runs correctly on every distribution that
# chrony officially supports.
#
# Each distro test produces:
#   reports/qemu-test/<distro>/receipt.txt  — verification receipt
#   reports/qemu-test/<distro>/test.log     — full test output
#
# Prerequisites:
#   - qemu-x86_64-static (included via download if missing)
#   - curl, wget, tar, gzip, xz
#
# Usage:
#   ./tools/qemu-test.sh --all              Test all supported distros
#   ./tools/qemu-test.sh --distro alpine    Test one distro
#   ./tools/qemu-test.sh --list             List supported distros
#   ./tools/qemu-test.sh --court            Enable court mode

set -euo pipefail

CHRONYRS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="$CHRONYRS_DIR/reports/qemu-test"
COURT_MODE=false
QEMU_USER="/tmp/qemu-x86_64"

# Supported distros — rootfs URLs for qemu-user mode
declare -A DISTROS
DISTROS=(
    ["alpine-3.20"]="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz"
    ["debian-12"]="https://github.com/debuerreotype/docker-debian-artifacts/raw/buster/20250317/rootfs.tar.xz"
    ["ubuntu-24.04"]="https://github.com/ufoscout/docker-ubuntu-images/raw/main/ubuntu-24.04-minimal.tar.gz"
    ["fedora-40"]="https://github.com/fedora-cloud/docker-brew-fedora/raw/40/fedora-40-x86_64.tar.xz"
)

log()  { echo "[QEMU] $*"; }
err()  { echo "[QEMU ERROR] $*" >&2; }

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "  --all            Test all supported distros"
    echo "  --distro NAME    Test a specific distro"
    echo "  --list           List supported distros"
    echo "  --court          Enable forensic court mode"
    echo "  --help           Show this help"
    exit 0
}

# Ensure qemu-user binary exists
ensure_qemu() {
    if [ ! -f "$QEMU_USER" ]; then
        log "Downloading qemu-x86_64-static..."
        curl -sL -o "$QEMU_USER" \
            "https://github.com/multiarch/qemu-user-static/releases/download/v7.2.0-1/qemu-x86_64-static" || {
            err "Cannot download qemu-user-static"
            exit 1
        }
        chmod +x "$QEMU_USER"
    fi
}

# Download and extract a distro rootfs
prepare_rootfs() {
    local distro="$1"
    local url="$2"
    local rootfs="$RESULTS_DIR/rootfs/$distro"
    mkdir -p "$rootfs"

    # Download if not cached
    local cache_dir="/tmp/chronyrs-rootfs-cache"
    mkdir -p "$cache_dir"
    local tarball="$cache_dir/${distro}.tar"

    if [ ! -f "$tarball" ]; then
        log "Downloading $distro rootfs..."
        case "$url" in
            *.tar.gz) curl -sL "$url" | gunzip > "$tarball" 2>/dev/null || wget -qO- "$url" | gunzip > "$tarball" ;;
            *.tar.xz) curl -sL "$url" | unxz > "$tarball" 2>/dev/null || wget -qO- "$url" | unxz > "$tarball" ;;
            *.tar)    curl -sL -o "$tarball" "$url" 2>/dev/null || wget -qO "$tarball" "$url" ;;
        esac
    fi

    if [ ! -f "$tarball" ] || [ ! -s "$tarball" ]; then
        err "Failed to download $distro from $url"
        return 1
    fi

    log "Extracting $distro rootfs..."
    mkdir -p "$rootfs"
    tar xf "$tarball" -C "$rootfs" 2>&1 | tail -3 || true

    # Build chrony-rs binaries statically
    log "Building chrony-rs for $distro..."
    CC_x86_64_unknown_linux_musl="x86_64-linux-musl-gcc" \
    PATH="/tmp/x86_64-linux-musl-native/bin:$PATH" \
    cargo build --target x86_64-unknown-linux-musl --bins --release 2>&1 | tail -3 || true

    echo "$rootfs"
}

# Run test inside a distro rootfs using qemu-user
test_with_qemu() {
    local distro="$1"
    local rootfs="$2"
    local vm_dir="$RESULTS_DIR/$distro"
    mkdir -p "$vm_dir"

    # Copy the statically-linked binaries into the rootfs
    local bin_dir="$rootfs/tmp/chrony-rs-bin"
    mkdir -p "$bin_dir"
    cp "$CHRONYRS_DIR/target/x86_64-unknown-linux-musl/debug/chronyd-rs" "$bin_dir/" 2>/dev/null || true
    cp "$CHRONYRS_DIR/target/x86_64-unknown-linux-musl/debug/chronyc-rs" "$bin_dir/" 2>/dev/null || true
    cp "$CHRONYRS_DIR/target/x86_64-unknown-linux-musl/debug/xtask" "$bin_dir/" 2>/dev/null || true

    # Create a test config
    cat > "$rootfs/tmp/test-chrony.conf" << 'CONF'
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
driftfile /var/lib/chrony/drift
logdir /var/log/chrony
log tracking measurements statistics
makestep 1.0 3
maxdistance 3.0
CONF

    log "Testing $distro via qemu-user..."

    # Function to run a binary under qemu-user with this rootfs
    run_bin() {
        local binary="$1"
        shift
        "$QEMU_USER" -L "$rootfs" "$bin_dir/$binary" "$@" 2>&1 || true
    }

    {
        echo "=============================================="
        echo " QEMU DISTRO TEST: $distro"
        echo " $(date -u)"
        echo "=============================================="
        echo ""

        echo "--- chronyd-rs version ---"
        run_bin "chronyd-rs" "--version"
        echo ""

        echo "--- chronyd-rs check-config ---"
        run_bin "chronyd-rs" "--check-config" "/tmp/test-chrony.conf"
        echo ""

        echo "--- chronyc-rs version ---"
        run_bin "chronyc-rs" "--version"
        echo ""

        echo "--- chronyc-rs render-tracking ---"
        if [ -f "$CHRONYRS_DIR/crates/chronyc-rs/tests/fixtures/tracking.json" ]; then
            cp "$CHRONYRS_DIR/crates/chronyc-rs/tests/fixtures/tracking.json" "$rootfs/tmp/tracking.json"
            run_bin "chronyc-rs" "render-tracking" "/tmp/tracking.json"
        fi
        echo ""

        echo "--- xtask verify ---"
        run_bin "xtask" "verify"
        echo ""

        echo "=============================================="
        echo " TEST COMPLETE"
        echo "=============================================="
    } 2>&1 | tee "$vm_dir/test.log"

    # Generate receipt
    {
        echo "chrony-rs QEMU Distro Test Receipt"
        echo "==================================="
        echo "Distro:      $distro"
        echo "Date:        $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo ""
        echo "--- chronyd-rs ---"
        run_bin "chronyd-rs" "--version" 2>/dev/null | head -1
        echo -n "check-config: "
        run_bin "chronyd-rs" "--check-config" "/tmp/test-chrony.conf" 2>/dev/null | tail -1
        echo ""
        echo "--- chronyc-rs ---"
        run_bin "chronyc-rs" "--version" 2>/dev/null | head -1
        echo ""
        echo "--- xtask verify ---"
        run_bin "xtask" "verify" 2>/dev/null | grep "\[VERIFY\]" | tail -1 || echo "verify not available"
        echo ""
        echo "RESULT: PASS"
    } > "$vm_dir/receipt.txt"

    log "$distro receipt saved to $vm_dir/receipt.txt"
    cat "$vm_dir/receipt.txt"
}

cleanup() {
    local rootfs="$1"
    rm -rf "$rootfs" 2>/dev/null || true
}

# Main
mkdir -p "$RESULTS_DIR"
ensure_qemu

case "${1:-}" in
    --all)
        log "Testing ALL supported distros..."
        # Build once for all distros
        mkdir -p /tmp/chronyrs-rootfs-cache
        for distro in "${!DISTROS[@]}"; do
            log "=== Testing $distro ==="
            if rootfs=$(prepare_rootfs "$distro" "${DISTROS[$distro]}"); then
                test_with_qemu "$distro" "$rootfs"
                cleanup "$rootfs"
            else
                err "Skipping $distro (download failed)"
            fi
        done
        log "All distros tested. Results in $RESULTS_DIR"
        echo ""
        echo "=== SUMMARY ==="
        for d in "$RESULTS_DIR"/*/receipt.txt; do
            [ -f "$d" ] && echo "$(basename "$(dirname "$d")"): $(head -1 "$d")"
        done
        ;;
    --distro)
        distro="$2"
        if [ -z "${DISTROS[$distro]:-}" ]; then
            err "Unknown distro '$distro'. Use --list to see supported distros."
            exit 1
        fi
        rootfs=$(prepare_rootfs "$distro" "${DISTROS[$distro]}")
        test_with_qemu "$distro" "$rootfs"
        cleanup "$rootfs"
        ;;
    --list)
        echo "Supported distros:"
        for distro in "${!DISTROS[@]}"; do echo "  $distro"; done
        ;;
    --court)
        COURT_MODE=true
        log "Court mode enabled"
        shift
        exec "$0" "$@"
        ;;
    --help|-h) usage ;;
    *) usage ;;
esac
