#!/usr/bin/env bash
# build-fedora-cloud.sh — Download and prepare Fedora Cloud image for Cloud Hypervisor.
#
# Must be run as root on a Linux host with qemu-img and guestfish installed.
#
# Usage:
#   sudo ./scripts/build-fedora-cloud.sh [--image-size SIZE]
#
# Options:
#   --image-size SIZE    Size for the image (default: 10G)
#
# What it does:
#   1. Downloads the official Fedora Cloud Base qcow2 image
#   2. Converts it to raw format and resizes
#   3. Uses virt-customize to install packages and configure the system
#
# After this script succeeds, run `sudo ./scripts/bake-agent.sh --os fedora`
# to inject the minions-agent binary and systemd service.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
IMAGE_SIZE="${IMAGE_SIZE:-10G}"
IMAGES_DIR="${IMAGES_DIR:-/var/lib/minions/images}"
FEDORA_VERSION="43"
FEDORA_CLOUD_URL="https://download.fedoraproject.org/pub/fedora/linux/releases/${FEDORA_VERSION}/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-${FEDORA_VERSION}-1.6.x86_64.qcow2"
TEMP_QCOW2="/tmp/fedora-cloud-$$.qcow2"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --image-size)
            IMAGE_SIZE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--image-size SIZE]" >&2
            exit 1
            ;;
    esac
done

BASE_IMAGE="$IMAGES_DIR/base-fedora.ext4"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "  [fedora-cloud] $*"; }
ok()    { echo "✓ $*"; }
fail()  { echo "✗ $*" >&2; exit 1; }

cleanup() {
    rm -f "$TEMP_QCOW2" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preconditions ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "must be run as root (sudo $0)"

if ! command -v qemu-img &>/dev/null; then
    fail "qemu-img not found — install it first (apt install qemu-utils)"
fi

if ! command -v virt-customize &>/dev/null; then
    fail "virt-customize not found — install it first (apt install libguestfs-tools)"
fi

if ! command -v wget &>/dev/null && ! command -v curl &>/dev/null; then
    fail "wget or curl required for downloading"
fi

# ── Step 1: Download Fedora Cloud image ──────────────────────────────────────
info "downloading Fedora $FEDORA_VERSION Cloud image…"
if command -v wget &>/dev/null; then
    wget -q --show-progress -O "$TEMP_QCOW2" "$FEDORA_CLOUD_URL" || fail "wget failed"
else
    curl -L --progress-bar -o "$TEMP_QCOW2" "$FEDORA_CLOUD_URL" || fail "curl failed"
fi
ok "downloaded $(du -sh "$TEMP_QCOW2" | cut -f1))"

# ── Step 2: Resize qcow2 image ────────────────────────────────────────────────
info "resizing to $IMAGE_SIZE…"
qemu-img resize "$TEMP_QCOW2" "$IMAGE_SIZE" || fail "qemu-img resize failed"
ok "resized to $IMAGE_SIZE"

# ── Step 3: Convert to raw format ─────────────────────────────────────────────
mkdir -p "$IMAGES_DIR"

# Backup existing image if it exists
if [[ -f "$BASE_IMAGE" ]]; then
    BACKUP="${BASE_IMAGE}.backup-$(date +%s)"
    info "backing up existing image to $BACKUP"
    mv "$BASE_IMAGE" "$BACKUP"
fi

info "converting to raw format → $BASE_IMAGE…"
qemu-img convert -f qcow2 -O raw "$TEMP_QCOW2" "$BASE_IMAGE" || fail "qemu-img convert failed"
ok "converted to raw ($(du -sh "$BASE_IMAGE" | cut -f1))"

# ── Step 4: Customize with virt-customize ────────────────────────────────────
info "customizing image (this may take a few minutes)…"

virt-customize -a "$BASE_IMAGE" \
    --uninstall cloud-init \
    --delete "/etc/cloud" \
    --delete "/var/lib/cloud" \
    --run-command "systemctl enable sshd" \
    --mkdir /root/.ssh:mode:0700 \
    --run-command "passwd -l root" \
    --run-command "sed -i 's/#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config" \
    --run-command "sed -i 's/#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config" \
    --write "/etc/hostname:minion" \
    || fail "virt-customize failed"

ok "image customized"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "Fedora $FEDORA_VERSION Cloud image prepared successfully!"
echo ""
echo "  Image:  $BASE_IMAGE"
echo "  Size:   $IMAGE_SIZE"
echo "  Actual: $(du -sh "$BASE_IMAGE" | cut -f1)"
echo ""
echo "  Next step:  sudo ./scripts/bake-agent.sh --os fedora"
echo "────────────────────────────────────────────"
