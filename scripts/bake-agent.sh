#!/usr/bin/env bash
# bake-agent.sh — Inject minions-agent (+ systemd unit) into the base Ubuntu
# rootfs image so every subsequent `minions create` gets the agent for free.
#
# Must be run as root on a Linux host with loop-mount support.
#
# Prerequisites:
#   - Pre-built binaries installed (run install.sh first or set BINARIES_DIR)
#   - Base rootfs image at /var/lib/minions/images/base-ubuntu.ext4
#
# Usage:
#   sudo ./scripts/bake-agent.sh
#   sudo BINARIES_DIR=/path/to/extracted/release ./scripts/bake-agent.sh
#
# What it does:
#   1. Verifies minions and minions-agent binaries are available
#   2. Mounts /var/lib/minions/images/base-ubuntu.ext4 via a loop device
#   3. Copies the agent binary to /usr/local/bin/minions-agent inside the image
#   4. Writes the systemd unit /etc/systemd/system/minions-agent.service
#   5. Creates the multi-user.target.wants symlink to auto-start the agent
#   6. Removes any leftover Phase-1 static network config that conflicts
#   7. Unmounts cleanly (even on failure)
#
# After this script succeeds, the base image is ready.  Every VM created with
# `minions create` will have the agent running from first boot.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
BASE_IMAGE="${BASE_IMAGE:-/var/lib/minions/images/base-ubuntu.ext4}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/minions-bake-mount}"
BINARIES_DIR="${BINARIES_DIR:-/usr/local/bin}"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "  [bake] $*"; }
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

[[ -f "$BASE_IMAGE" ]] || fail "base image not found: $BASE_IMAGE
  Build it first: sudo ./scripts/build-base-image.sh"

# ── Step 1: Verify binaries ───────────────────────────────────────────────────
info "verifying pre-built binaries in $BINARIES_DIR…"

AGENT_BIN="$BINARIES_DIR/minions-agent"
MINIONS_BIN="$BINARIES_DIR/minions"

[[ -f "$AGENT_BIN" ]]  || fail "minions-agent binary not found at $AGENT_BIN
  Install binaries first: curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash"

[[ -f "$MINIONS_BIN" ]] || fail "minions binary not found at $MINIONS_BIN
  Install binaries first: curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash"

ok "found $(du -sh "$AGENT_BIN" | cut -f1) agent, $(du -sh "$MINIONS_BIN" | cut -f1) CLI"

# ── Step 2: Verify minions CLI on the host ────────────────────────────────────
if [[ "$BINARIES_DIR" != "/usr/local/bin" ]] && [[ ! -x "/usr/local/bin/minions" ]]; then
    info "installing minions CLI → /usr/local/bin/minions"
    install -m 0755 "$MINIONS_BIN" /usr/local/bin/minions
    ok "minions CLI installed"
else
    ok "minions CLI already available"
fi

# ── Step 3: Mount base image ──────────────────────────────────────────────────
info "mounting base image $BASE_IMAGE → $MOUNT_DIR"
mkdir -p "$MOUNT_DIR"
mount -o loop "$BASE_IMAGE" "$MOUNT_DIR"
ok "mounted"

# ── Step 4: Inject agent binary ───────────────────────────────────────────────
info "copying agent binary → /usr/local/bin/minions-agent"
install -m 0755 "$AGENT_BIN" "$MOUNT_DIR/usr/local/bin/minions-agent"
ok "agent binary copied ($(du -sh "$MOUNT_DIR/usr/local/bin/minions-agent" | cut -f1))"

# ── Step 5: Write systemd unit ────────────────────────────────────────────────
info "writing minions-agent.service"
cat > "$MOUNT_DIR/etc/systemd/system/minions-agent.service" << 'EOF'
[Unit]
Description=Minions Guest Agent
# Wait for the vsock device to appear (virtio_vsock module loaded by kernel early)
After=systemd-modules-load.service
Wants=systemd-modules-load.service

[Service]
Type=simple
ExecStart=/usr/local/bin/minions-agent
Restart=always
RestartSec=1
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
ok "systemd unit written"

# ── Step 6: Enable via wants symlink ─────────────────────────────────────────
WANTS_DIR="$MOUNT_DIR/etc/systemd/system/multi-user.target.wants"
mkdir -p "$WANTS_DIR"
SYMLINK="$WANTS_DIR/minions-agent.service"
if [[ -L "$SYMLINK" ]]; then
    info "removing old symlink"
    rm "$SYMLINK"
fi
ln -sf /etc/systemd/system/minions-agent.service "$SYMLINK"
ok "service enabled (wants symlink created)"

# ── Step 7: Remove Phase-1 static network config ──────────────────────────────
info "removing any leftover static network config from Phase 1…"
rm -f "$MOUNT_DIR/etc/systemd/network/10-vm.network"
rm -f "$MOUNT_DIR/etc/systemd/system/vm-network.service"
rm -f "$MOUNT_DIR/etc/systemd/system/multi-user.target.wants/vm-network.service"
ok "static network config cleaned up"

# ── Step 8: Disable unnecessary services ──────────────────────────────────────
info "disabling getty services (tty1-6, ttyS0) to reduce memory…"
# Remove getty symlinks from multi-user.target.wants
rm -f "$MOUNT_DIR/etc/systemd/system/getty.target.wants/getty@tty"[1-6]".service"
rm -f "$MOUNT_DIR/etc/systemd/system/serial-getty@ttyS0.service"
# Mask them so they never start
for tty in tty{1..6}; do
    ln -sf /dev/null "$MOUNT_DIR/etc/systemd/system/getty@${tty}.service"
done
ln -sf /dev/null "$MOUNT_DIR/etc/systemd/system/serial-getty@ttyS0.service"
ok "getty services disabled (saves ~13 MB RAM)"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "base image baked successfully!"
echo ""
echo "  Agent binary : /usr/local/bin/minions-agent (inside image)"
echo "  Systemd unit : /etc/systemd/system/minions-agent.service (inside image)"
echo "  Host CLI     : /usr/local/bin/minions"
echo "  Optimizations: getty services disabled (~13 MB RAM saved per VM)"
echo ""
echo "  You can now run:  sudo minions create myvm"
echo "────────────────────────────────────────────"
