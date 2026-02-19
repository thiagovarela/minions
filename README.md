# Minions

A VM-as-a-Service platform built on Cloud Hypervisor with direct rootfs (no Kata runtime layer). Instant VMs on the internet, accessible over HTTPS and SSH.

## Quick Start

See `docs/` for full setup guides:
- `docs/phase-1-setup.md` — Provision the host, build kernel + base rootfs
- `docs/phase-2-setup.md` — Test guest agent via VSOCK
- `docs/phase-3-setup.md` — Bake agent into base image
- `docs/phase-4-setup.md` — VM lifecycle (create, list, delete)
- `docs/phase-5-setup.md` — SSH gateway
- `docs/phase-6-setup.md` — HTTPS reverse proxy
- `docs/phase-7-setup.md` — Multi-host architecture

## Build & Release

Minions uses **static Linux binaries** built via cross-compilation from macOS to `x86_64-unknown-linux-musl`. Releases are published to GitHub with pre-built binaries.

### Prerequisites (Development)

**On macOS:**
```bash
# Install musl cross-compiler (one-time, ~15 min first run)
brew install FiloSottile/musl-cross/musl-cross

# Add Rust Linux target
rustup target add x86_64-unknown-linux-musl
```

**On Linux server:**
```bash
# No Rust toolchain needed — just download pre-built binaries
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
```

### Build Locally

```bash
# Build all binaries for Linux
mise run build

# Create a release tarball (dist/minions-<version>-x86_64-unknown-linux-musl.tar.gz)
mise run release
```

### Publish a Release

```bash
# Build + create GitHub Release with binaries attached
mise run publish VERSION=v0.2.0
```

This will:
1. Build all binaries (`minions`, `minions-agent`, `minions-node`, `minions-vsock-cli`)
2. Create a tarball
3. Create a git tag (if it doesn't exist)
4. Create a GitHub Release with the tarball attached

### Deploy to Linux Server

**Install binaries:**
```bash
# Latest release
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash

# Specific version
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash -s -- v0.2.0
```

**Bake agent into VM base image:**
```bash
# After installing binaries, update the base rootfs image
sudo /usr/local/bin/minions bake-agent

# Or run the script directly
sudo ./scripts/bake-agent.sh
```

This injects `minions-agent` into `/var/lib/minions/images/base-ubuntu.ext4` so all new VMs have the agent pre-installed.

## Development Workflow

```bash
# 1. Make changes
git checkout -b feat/my-feature

# 2. Build locally (macOS)
mise run build

# 3. Test on Linux server
scp target/x86_64-unknown-linux-musl/release/minions user@server:/tmp/
ssh user@server sudo install -m 0755 /tmp/minions /usr/local/bin/minions

# 4. Commit + push
git commit -am "feat: my awesome feature"
git push origin feat/my-feature

# 5. Create PR, merge to main

# 6. Publish release
git checkout main
git pull
mise run publish VERSION=v0.3.0
```

## Architecture

See `docs/sketch-plan.md` for the full design.

**High-level:**
- **Guest agent** (`minions-agent`) runs inside each VM, listens on VSOCK for control commands
- **Host daemon** (`minions`) manages VM lifecycle (create, delete, restart), SSH gateway, HTTPS proxy
- **Node agent** (`minions-node`) runs on each physical host in multi-host mode
- **Communication:** VSOCK for host↔guest, HTTP/JSON for CLI↔daemon and daemon↔node

**Storage:**
- LVM thin provisioning for instant VM creation (copy-on-write snapshots)
- Each VM has two disks: rootfs (ephemeral, snapshot of base image) + data (persistent)

**Networking:**
- Bridge (`br0`) with NAT for VM internet access
- TAP devices per VM, IP allocation from pool (SQLite)
- Wildcard DNS (`*.yourdomain.xyz`) → HTTPS proxy routes by subdomain

## License

MIT (or whatever you choose)
