#!/usr/bin/env bash
# build-nixos-image.sh — Build a NixOS base image for Cloud Hypervisor VMs.
#
# Must be run as root on a Linux host with Nix installed.
#
# Usage:
#   sudo ./scripts/build-nixos-image.sh
#
# What it does:
#   1. Checks for Nix installation
#   2. Builds the NixOS image via flake in images/nixos/
#   3. Extracts the vmlinux kernel and initramfs from the NixOS build
#   4. Copies the image to /var/lib/minions/images/base-nixos.ext4
#   5. Copies the kernel to /var/lib/minions/kernel/vmlinux-nixos
#   6. Copies the initramfs to /var/lib/minions/kernel/initrd-nixos
#   7. Injects the minions-agent binary into the image
#
# Unlike Ubuntu/Fedora, NixOS does NOT require a separate bake-agent.sh step.
# The agent service is defined in the NixOS configuration, and the binary is
# injected during this script.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
IMAGES_DIR="${IMAGES_DIR:-/var/lib/minions/images}"
KERNEL_DIR="${KERNEL_DIR:-/var/lib/minions/kernel}"
BINARIES_DIR="${BINARIES_DIR:-/usr/local/bin}"
NIXOS_FLAKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../images/nixos" && pwd)"
BASE_IMAGE="$IMAGES_DIR/base-nixos.ext4"
KERNEL_PATH="$KERNEL_DIR/vmlinux-nixos"
INITRD_PATH="$KERNEL_DIR/initrd-nixos"
AGENT_BIN="$BINARIES_DIR/minions-agent"
MOUNT_DIR="${MOUNT_DIR:-/tmp/minions-nixos-mount}"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "  [nixos] $*"; }
ok()    { echo "✓ $*"; }
fail()  { echo "✗ $*" >&2; exit 1; }

cleanup() {
    if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
        info "unmounting $MOUNT_DIR…"
        umount "$MOUNT_DIR" || true
    fi
    rmdir "$MOUNT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preconditions ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "must be run as root (sudo $0)"

if ! command -v nix &>/dev/null; then
    fail "nix not found — install it first:
  curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
  (or: sh <(curl -L https://nixos.org/nix/install) --daemon)"
fi

if [[ ! -f "$AGENT_BIN" ]]; then
    fail "minions-agent binary not found at $AGENT_BIN
  Build and install binaries first:
    curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
  Or build from source:
    mise run build && sudo install -m 0755 target/x86_64-unknown-linux-musl/release/minions-agent $AGENT_BIN"
fi

ok "found Nix and minions-agent ($(du -sh "$AGENT_BIN" | cut -f1))"

# ── Step 1: Build NixOS image + kernel ───────────────────────────────────────
info "building NixOS image (this may take 5-10 minutes on first build)…"
cd "$NIXOS_FLAKE_DIR"

# Build both the image and kernel in one go
RESULT=$(nix build .#default --no-link --print-out-paths 2>&1 | tail -1)
if [[ ! -d "$RESULT" ]]; then
    fail "nix build failed — check output above"
fi
ok "NixOS image built at $RESULT"

# ── Step 2: Copy image to images directory ───────────────────────────────────
info "installing base image…"
mkdir -p "$IMAGES_DIR"

# Backup existing image if it exists
if [[ -f "$BASE_IMAGE" ]]; then
    BACKUP="${BASE_IMAGE}.backup-$(date +%s)"
    info "backing up existing image to $BACKUP"
    mv "$BASE_IMAGE" "$BACKUP"
fi

cp "$RESULT/base-nixos.ext4" "$BASE_IMAGE" || fail "failed to copy image"
ok "image installed at $BASE_IMAGE ($(du -sh "$BASE_IMAGE" | cut -f1))"

# ── Step 3: Copy kernel to kernel directory ──────────────────────────────────
info "installing NixOS kernel…"
mkdir -p "$KERNEL_DIR"

# Backup existing kernel if it exists
if [[ -f "$KERNEL_PATH" ]]; then
    BACKUP="${KERNEL_PATH}.backup-$(date +%s)"
    info "backing up existing kernel to $BACKUP"
    mv "$KERNEL_PATH" "$BACKUP"
fi

cp "$RESULT/vmlinux-nixos" "$KERNEL_PATH" || fail "failed to copy kernel"
ok "kernel installed at $KERNEL_PATH ($(du -sh "$KERNEL_PATH" | cut -f1))"

# ── Step 3b: Copy initramfs ──────────────────────────────────────────────────
info "installing NixOS initramfs…"
if [[ -f "$INITRD_PATH" ]]; then
    BACKUP="${INITRD_PATH}.backup-$(date +%s)"
    info "backing up existing initramfs to $BACKUP"
    mv "$INITRD_PATH" "$BACKUP"
fi

cp "$RESULT/initrd-nixos" "$INITRD_PATH" || fail "failed to copy initramfs"
ok "initramfs installed at $INITRD_PATH ($(du -sh "$INITRD_PATH" | cut -f1))"

# ── Step 4: Inject minions-agent binary ──────────────────────────────────────
info "injecting minions-agent binary into image…"
mkdir -p "$MOUNT_DIR"
mount -o loop "$BASE_IMAGE" "$MOUNT_DIR" || fail "mount failed"
ok "mounted"

info "copying agent binary → /usr/local/bin/minions-agent"
mkdir -p "$MOUNT_DIR/usr/local/bin"
install -m 0755 "$AGENT_BIN" "$MOUNT_DIR/usr/local/bin/minions-agent"
ok "agent binary injected ($(du -sh "$MOUNT_DIR/usr/local/bin/minions-agent" | cut -f1))"

# NixOS stage-1 expects /init inside the mounted rootfs.
# make-disk-image does not always create this symlink for our boot flow,
# so create it explicitly to ensure stage-2 handoff succeeds.
ln -sfn /nix/var/nix/profiles/system/init "$MOUNT_DIR/init"
ok "created /init symlink for stage-2 handoff"

info "unmounting…"
umount "$MOUNT_DIR" || fail "umount failed"
rmdir "$MOUNT_DIR"
ok "unmounted and cleaned up"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "NixOS base image built successfully!"
echo ""
echo "  Image:     $BASE_IMAGE"
echo "  Kernel:    $KERNEL_PATH"
echo "  Initramfs: $INITRD_PATH"
echo "  Actual:    $(du -sh "$BASE_IMAGE" | cut -f1) (image), $(du -sh "$KERNEL_PATH" | cut -f1) (kernel), $(du -sh "$INITRD_PATH" | cut -f1) (initrd)"
echo ""
echo "  The minions-agent is already baked in — no separate bake step needed."
echo ""
echo "  You can now run:  sudo minions create myvm --os nixos"
echo "────────────────────────────────────────────"
