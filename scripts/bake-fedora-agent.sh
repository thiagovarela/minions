#!/usr/bin/env bash
# bake-fedora-agent.sh — Inject minions-agent into Fedora Cloud image using guestfish.
#
# Must be run as root on a Linux host with libguestfs installed.
#
# Usage:
#   sudo ./scripts/bake-fedora-agent.sh
#
# What it does:
#   1. Verifies minions-agent binary exists
#   2. Uses guestfish to inject agent binary and systemd unit into the Fedora image
#   3. Enables the minions-agent service
#   4. Disables unnecessary getty services

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
IMAGES_DIR="${IMAGES_DIR:-/var/lib/minions/images}"
BINARIES_DIR="${BINARIES_DIR:-/usr/local/bin}"
BASE_IMAGE="$IMAGES_DIR/base-fedora.ext4"
AGENT_BIN="$BINARIES_DIR/minions-agent"
MINIONS_BIN="$BINARIES_DIR/minions"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "  [bake-fedora] $*"; }
ok()    { echo "✓ $*"; }
fail()  { echo "✗ $*" >&2; exit 1; }

# ── Preconditions ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "must be run as root (sudo $0)"

[[ -f "$BASE_IMAGE" ]] || fail "base image not found: $BASE_IMAGE
  Build it first: sudo ./scripts/build-fedora-cloud.sh"

[[ -f "$AGENT_BIN" ]]  || fail "minions-agent binary not found at $AGENT_BIN"
[[ -f "$MINIONS_BIN" ]] || fail "minions binary not found at $MINIONS_BIN"

if ! command -v guestfish &>/dev/null; then
    fail "guestfish not found — install it first (apt install libguestfs-tools)"
fi

info "verifying binaries…"
ok "found $(du -sh "$AGENT_BIN" | cut -f1) agent, $(du -sh "$MINIONS_BIN" | cut -f1) CLI"

# ── Step 1: Create systemd unit file ──────────────────────────────────────────
TEMP_UNIT="/tmp/minions-agent.service.$$"
cat > "$TEMP_UNIT" << 'EOF'
[Unit]
Description=Minions Guest Agent
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

# ── Step 2: Use guestfish to inject files ─────────────────────────────────────
info "injecting agent and systemd unit into image…"

guestfish -a "$BASE_IMAGE" -i << _EOF_
# Upload agent binary
upload $AGENT_BIN /usr/local/bin/minions-agent
chmod 0755 /usr/local/bin/minions-agent

# Upload systemd unit
upload $TEMP_UNIT /etc/systemd/system/minions-agent.service

# Enable the service
ln-sf /etc/systemd/system/minions-agent.service /etc/systemd/system/multi-user.target.wants/minions-agent.service

# Disable getty services to save RAM
ln-sf /dev/null /etc/systemd/system/getty@tty1.service
ln-sf /dev/null /etc/systemd/system/getty@tty2.service
ln-sf /dev/null /etc/systemd/system/getty@tty3.service
ln-sf /dev/null /etc/systemd/system/getty@tty4.service
ln-sf /dev/null /etc/systemd/system/getty@tty5.service
ln-sf /dev/null /etc/systemd/system/getty@tty6.service
ln-sf /dev/null /etc/systemd/system/serial-getty@ttyS0.service
_EOF_

rm -f "$TEMP_UNIT"
ok "agent injected and service enabled"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "Fedora Cloud image baked successfully!"
echo ""
echo "  Agent binary : /usr/local/bin/minions-agent (inside image)"
echo "  Systemd unit : /etc/systemd/system/minions-agent.service (inside image)"
echo "  Optimizations: getty services disabled (~13 MB RAM saved per VM)"
echo ""
echo "  You can now run:  sudo minions create myvm --os fedora"
echo "────────────────────────────────────────────"
