#!/usr/bin/env bash
# build-base-image.sh — Build a base rootfs for Cloud Hypervisor VMs.
#
# Must be run as root on a Linux host with Docker installed.
#
# Usage:
#   sudo ./scripts/build-base-image.sh [--os OS] [--image-size SIZE]
#
# Options:
#   --os OS              OS to build: ubuntu (default), fedora
#   --image-size SIZE    Size for the ext4 image (default: 5G)
#
# What it does:
#   1. Builds the Dockerfile at images/Dockerfile[.os] → minions-base-{os} Docker image
#   2. Exports the Docker container filesystem to a tarball
#   3. Creates a sparse ext4 image at /var/lib/minions/images/base-{os}.ext4
#   4. Mounts the image via loop device
#   5. Extracts the tarball into the mounted image
#   6. Unmounts and cleans up
#
# After this script succeeds, run `sudo minions bake-agent --os {os}` 
# (or sudo ./scripts/bake-agent.sh --os {os}) to inject the minions-agent 
# binary and systemd service into the base image.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
OS="${OS:-ubuntu}"
IMAGE_SIZE="${IMAGE_SIZE:-5G}"
IMAGES_DIR="${IMAGES_DIR:-/var/lib/minions/images}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/minions-rootfs-mount}"
DOCKERFILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/images"
TEMP_TARBALL="/tmp/minions-rootfs-$$.tar"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --os)
            OS="$2"
            shift 2
            ;;
        --image-size)
            IMAGE_SIZE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [--os ubuntu|fedora|nixos] [--image-size SIZE]" >&2
            exit 1
            ;;
    esac
done

# Validate OS
case "$OS" in
    ubuntu)
        DOCKERFILE="$DOCKERFILE_DIR/Dockerfile"
        ;;
    fedora)
        DOCKERFILE="$DOCKERFILE_DIR/Dockerfile.fedora"
        ;;
    nixos)
        # Delegate to NixOS-specific build script
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        exec "$SCRIPT_DIR/build-nixos-image.sh"
        ;;
    *)
        echo "✗ Unknown OS: $OS (supported: ubuntu, fedora, nixos)" >&2
        exit 1
        ;;
esac

BASE_IMAGE="$IMAGES_DIR/base-$OS.ext4"
DOCKER_IMAGE="minions-base-$OS"
CONTAINER_NAME="minions-export-$OS"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()  { echo "  [build:$OS] $*"; }
ok()    { echo "✓ $*"; }
fail()  { echo "✗ $*" >&2; exit 1; }

cleanup() {
    if mountpoint -q "$MOUNT_DIR" 2>/dev/null; then
        info "unmounting $MOUNT_DIR…"
        umount "$MOUNT_DIR" || true
    fi
    rmdir "$MOUNT_DIR" 2>/dev/null || true
    rm -f "$TEMP_TARBALL" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

# ── Preconditions ─────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "must be run as root (sudo $0)"

if ! command -v docker &>/dev/null; then
    fail "docker not found — install it first (apt install docker.io)"
fi

if [[ ! -f "$DOCKERFILE" ]]; then
    fail "Dockerfile not found at $DOCKERFILE"
fi

# ── Step 1: Build Docker image ────────────────────────────────────────────────
info "building Docker image from $DOCKERFILE…"
docker build -t "$DOCKER_IMAGE" -f "$DOCKERFILE" "$DOCKERFILE_DIR" || fail "docker build failed"
ok "Docker image '$DOCKER_IMAGE' built"

# ── Step 2: Export Docker container filesystem ────────────────────────────────
info "exporting Docker container filesystem to tarball…"
docker create --name "$CONTAINER_NAME" "$DOCKER_IMAGE" /bin/true || fail "docker create failed"
docker export "$CONTAINER_NAME" > "$TEMP_TARBALL" || fail "docker export failed"
docker rm "$CONTAINER_NAME" || true
ok "exported to $TEMP_TARBALL ($(du -sh "$TEMP_TARBALL" | cut -f1))"

# ── Step 3: Create sparse ext4 image ──────────────────────────────────────────
info "creating $IMAGE_SIZE sparse ext4 image at $BASE_IMAGE…"
mkdir -p "$IMAGES_DIR"

# Backup existing image if it exists
if [[ -f "$BASE_IMAGE" ]]; then
    BACKUP="${BASE_IMAGE}.backup-$(date +%s)"
    info "backing up existing image to $BACKUP"
    mv "$BASE_IMAGE" "$BACKUP"
fi

truncate -s "$IMAGE_SIZE" "$BASE_IMAGE" || fail "truncate failed"
mkfs.ext4 -F -L "rootfs-$OS" "$BASE_IMAGE" >/dev/null 2>&1 || fail "mkfs.ext4 failed"
ok "created $IMAGE_SIZE ext4 image"

# ── Step 4: Mount and extract tarball ─────────────────────────────────────────
info "mounting image at $MOUNT_DIR…"
mkdir -p "$MOUNT_DIR"
mount -o loop "$BASE_IMAGE" "$MOUNT_DIR" || fail "mount failed"
ok "mounted"

info "extracting tarball into image…"
tar xf "$TEMP_TARBALL" -C "$MOUNT_DIR" || fail "tar extract failed"
ok "tarball extracted"

# ── Step 5: Unmount and cleanup ───────────────────────────────────────────────
info "unmounting…"
umount "$MOUNT_DIR" || fail "umount failed"
rmdir "$MOUNT_DIR"
rm -f "$TEMP_TARBALL"
ok "unmounted and cleaned up"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
ok "base image for $OS built successfully!"
echo ""
echo "  Image:  $BASE_IMAGE"
echo "  Size:   $IMAGE_SIZE (sparse)"
echo "  Actual: $(du -sh "$BASE_IMAGE" | cut -f1)"
echo ""
echo "  Next step:  sudo minions bake-agent --os $OS"
echo "              (or: sudo ./scripts/bake-agent.sh --os $OS)"
echo "────────────────────────────────────────────"
