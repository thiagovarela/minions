#!/usr/bin/env bash
# Minions installer — download and install pre-built Linux binaries from GitHub Releases
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash -s -- v0.1.0
#
# What it does:
#   1. Validates platform (x86_64 + Linux only)
#   2. Downloads the tarball from the specified GitHub Release (or latest)
#   3. Extracts binaries to /usr/local/bin/
#   4. Verifies installation

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
REPO="thiagovarela/minions"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${1:-latest}"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[minions]${NC} $*"; }
warn()  { echo -e "${YELLOW}[minions]${NC} $*"; }
fail()  { echo -e "${RED}[minions]${NC} $*" >&2; exit 1; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }

# ── Preconditions ─────────────────────────────────────────────────────────────
info "Minions installer"
echo ""

# Check platform
ARCH="$(uname -m)"
OS="$(uname -s)"

if [ "$OS" != "Linux" ]; then
    fail "Unsupported OS: $OS (only Linux is supported)"
fi

if [ "$ARCH" != "x86_64" ]; then
    fail "Unsupported architecture: $ARCH (only x86_64 is supported)"
fi

TARGET="x86_64-unknown-linux-musl"
ok "Platform: $OS $ARCH (target: $TARGET)"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        fail "sudo not found. Please run as root or install sudo."
    fi
    SUDO="sudo"
    warn "Not running as root. Will use sudo for installation to $INSTALL_DIR."
fi

# ── Resolve version ──────────────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release version..."
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        fail "Failed to fetch latest release version from GitHub API"
    fi
    ok "Latest version: $VERSION"
else
    info "Using specified version: $VERSION"
fi

TARBALL="minions-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$TARBALL"

# ── Download ─────────────────────────────────────────────────────────────────
TMPDIR="$(mktemp -d)"
trap "rm -rf '$TMPDIR'" EXIT

info "Downloading $TARBALL from GitHub..."
if ! curl -sSL --fail "$URL" -o "$TMPDIR/$TARBALL"; then
    fail "Failed to download $URL. Check that the release exists."
fi
ok "Downloaded $(du -h "$TMPDIR/$TARBALL" | cut -f1)"

# ── Extract ──────────────────────────────────────────────────────────────────
info "Extracting binaries..."
tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"
ok "Extracted"

# ── Install ──────────────────────────────────────────────────────────────────
info "Installing to $INSTALL_DIR..."
BINARIES=(minions minions-agent minions-node minions-vsock-cli)

for bin in "${BINARIES[@]}"; do
    if [ ! -f "$TMPDIR/$bin" ]; then
        warn "Binary $bin not found in tarball, skipping"
        continue
    fi
    $SUDO install -m 0755 "$TMPDIR/$bin" "$INSTALL_DIR/$bin"
    ok "Installed $INSTALL_DIR/$bin"
done

# ── Verify ───────────────────────────────────────────────────────────────────
info "Verifying installation..."
if command -v minions >/dev/null 2>&1; then
    VERSION_OUTPUT="$(minions --version 2>&1 || echo 'version check failed')"
    ok "minions installed: $VERSION_OUTPUT"
else
    warn "minions not found in PATH. You may need to add $INSTALL_DIR to PATH."
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "Installation complete!"
echo ""
echo "  Binaries installed to: $INSTALL_DIR"
echo "  Version: $VERSION"
echo ""
echo "  Next steps:"
echo "    - Run 'minions --help' to get started"
echo "    - Update the base VM image: sudo bake-agent.sh (if agent changed)"
echo "────────────────────────────────────────────"
