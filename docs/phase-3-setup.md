# Phase 3 — VM Manager Setup

This document covers the one-time host setup required before using the `minions` CLI.

## Prerequisites

- Phase 1/2 host setup complete (bridge `br0` at `10.0.0.1/16`, NAT, iptables)
- `cloud-hypervisor` binary on `$PATH`
- `/var/lib/minions/kernel/vmlinux` — the Linux kernel image for guests
- `/var/lib/minions/images/base-ubuntu.ext4` — base rootfs **with agent pre-baked**

## Baking the agent into the base image (one-time)

A single script handles everything: build, mount, inject, enable, unmount, and
install the host CLI.

```bash
# On vps-2b1e18f2, from the repo root:
sudo ./scripts/bake-agent.sh
```

What the script does:
1. `cargo build --release -p minions-agent -p minions`
2. Installs `/usr/local/bin/minions` (host CLI) on vps-2b1e18f2
3. Mounts the base image via loop device
4. Copies the agent binary → `/usr/local/bin/minions-agent` inside the image
5. Writes `/etc/systemd/system/minions-agent.service` inside the image
6. Creates the `multi-user.target.wants` symlink to auto-start the agent
7. Removes any leftover Phase-1 static network config
8. Unmounts cleanly (even on failure, via `trap`)

> **Re-baking after agent changes:** just re-run `sudo ./scripts/bake-agent.sh`.
> The script is idempotent.

## Runtime directories

The CLI expects these paths to exist (created automatically on first use):

| Path | Purpose |
|------|---------|
| `/var/lib/minions/state.db` | SQLite VM state |
| `/var/lib/minions/vms/{name}/` | Per-VM rootfs and serial log |
| `/run/minions/` | CH API and VSOCK sockets |

## Usage

```bash
# Create a VM (default: 2 CPUs, 1024 MiB RAM)
sudo minions create myvm

# Create with custom resources
sudo minions create bigvm --cpus 4 --memory 2048

# List running VMs
sudo minions list

# Execute a command inside a VM
sudo minions exec myvm -- uname -a

# Open an interactive SSH session
sudo minions ssh myvm

# Show VM status from the agent
sudo minions status myvm

# Print the serial console log
sudo minions logs myvm

# Destroy a VM (graceful shutdown + full cleanup)
sudo minions destroy myvm
```

## Architecture

```
crates/minions/
└── src/
    ├── main.rs        # CLI entry point (clap)
    ├── vm.rs          # VM lifecycle orchestration
    ├── hypervisor.rs  # CH process spawn + API client
    ├── network.rs     # TAP create/destroy, MAC generation
    ├── storage.rs     # Rootfs copy + serial log helpers
    ├── agent.rs       # VSOCK client (connect, handshake, requests)
    └── db.rs          # SQLite state management
```

## IP & CID pools

- IP range: `10.0.0.2` – `10.0.0.254` (lowest unused allocated on `create`)
- VSOCK CID range: `3` – `255` (lowest unused allocated on `create`)
- MAC format: `52:54:00:00:{cid_high}:{cid_low}` (deterministic)
