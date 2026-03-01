# Minions

Instant VMs on the internet. Create, manage, and expose micro-VMs via a single CLI — with SSH access and HTTPS routing built in.

Minions runs on bare-metal Linux hosts with KVM. It uses [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) to boot lightweight Ubuntu VMs in ~3 seconds, each fully isolated with its own network, disk, and SSH keys.

## Getting started

### Install on your Linux server

```bash
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
```

This installs four binaries to `/usr/local/bin/`: `minions`, `minions-agent`, `minions-node`, and `minions-vsock-cli`.

> See [INSTALL.md](docs/INSTALL.md) for prerequisites (KVM, Cloud Hypervisor, kernel, base image) and full host setup.

### Initialize the host

After installing, run the one-time host setup:

```bash
sudo minions init          # bridge, iptables, directories
sudo minions init --persist # also persist networking across reboots
```

### Build the base image and bake in the agent

```bash
sudo ./scripts/build-base-image.sh  # Build Ubuntu 24.04 rootfs (default)
sudo ./scripts/bake-agent.sh        # Inject minions-agent
```

The first script builds a base Ubuntu 24.04 LTS rootfs with common dev tools (git, vim, htop, build-essential, etc.). The second injects the `minions-agent` binary so every new VM starts with the agent running.

**Multiple OS images:**

You can build and use different operating systems:

```bash
# Build Ubuntu 24.04 (default)
sudo ./scripts/build-base-image.sh --os ubuntu
sudo ./scripts/bake-agent.sh --os ubuntu

# Build Fedora 41
sudo ./scripts/build-base-image.sh --os fedora
sudo ./scripts/bake-agent.sh --os fedora

# Build NixOS 24.11 (requires Nix installed)
sudo ./scripts/build-base-image.sh --os nixos
# Note: NixOS doesn't need a separate bake-agent step
```

Images are stored at `/var/lib/minions/images/base-{os}.ext4`.

> See [INSTALL.md](docs/INSTALL.md) for full setup details.

## Using Minions

### Create a VM

```bash
sudo minions create myvm
```

Creates and boots a VM with 2 vCPUs and 1024 MiB RAM (defaults). Your local SSH public key is automatically injected.

```bash
sudo minions create myvm --cpus 4 --memory 2048
```

**Choose an operating system:**

```bash
sudo minions create myvm --os ubuntu   # Ubuntu 24.04 (default)
sudo minions create myvm --os fedora   # Fedora 41
sudo minions create myvm --os nixos    # NixOS 24.11
```

The base image for the chosen OS must be built first (see "Build the base image" above).

### List VMs

```bash
sudo minions list
```

```
 NAME   STATUS   IP         CPUS   MEMORY     PID
 myvm   running  10.0.0.2   2      1024 MiB   12345
 web    running  10.0.0.3   4      2048 MiB   12400
```

### SSH into a VM

```bash
sudo minions ssh myvm
```

Or connect directly:

```bash
ssh root@10.0.0.2
```

### Run commands inside a VM

```bash
sudo minions exec myvm -- uname -a
sudo minions exec myvm -- apt-get update
```

### Stop, start, and restart

```bash
sudo minions stop myvm
sudo minions start myvm
sudo minions restart myvm
```

### Resize a VM

Resize CPU, memory, or disk on a stopped VM:

```bash
sudo minions stop myvm
sudo minions resize myvm --cpus 4 --memory 4096 --disk 10
sudo minions start myvm
```

### Rename and copy VMs

```bash
sudo minions rename myvm production
sudo minions cp production staging
```

### Destroy a VM

```bash
sudo minions destroy myvm
```

Stops the VM, removes its disk, and deletes it from the database.

### View logs

```bash
sudo minions logs myvm
```

Prints the serial console output (useful for debugging boot issues).

### Check VM status

```bash
sudo minions status myvm
```

Returns status info from the guest agent running inside the VM.

## Snapshots

Create point-in-time snapshots of any VM (running or stopped):

```bash
sudo minions snapshot create myvm
sudo minions snapshot create myvm --name before-upgrade
sudo minions snapshot list myvm
sudo minions snapshot restore myvm before-upgrade
sudo minions snapshot delete myvm before-upgrade
```

## Running as a daemon

Start the HTTP API server to manage VMs remotely:

```bash
sudo minions serve
```

With SSH gateway and HTTPS proxy:

```bash
sudo minions serve \
  --ssh-bind 0.0.0.0:2222 \
  --proxy-bind 0.0.0.0:443 \
  --http-bind 0.0.0.0:80 \
  --domain mycloud.example.com \
  --public-ip 203.0.113.10 \
  --acme-email you@example.com
```

This gives you:
- **HTTP API** on port 3000 for programmatic VM management
- **SSH gateway** on port 2222 — connect to any VM via `ssh vmname@mycloud.example.com -p 2222`
- **HTTPS proxy** — each VM is reachable at `https://vmname.mycloud.example.com` (with automatic Let's Encrypt certificates)

### Remote CLI

When the daemon is running, the CLI auto-detects it and becomes a thin HTTP client — no `sudo` required:

```bash
minions list
minions create dev --cpus 2 --memory 2048
minions destroy dev
```

Or point at a remote server:

```bash
minions --host http://myserver:3000 --api-key SECRET list
```

### JSON output

All commands support `--json` for scripting:

```bash
minions list --json
minions create myvm --json
```

## Multi-host

Register multiple physical hosts and let Minions schedule VMs across them:

```bash
sudo minions host add node1 --address 10.0.1.1 --vcpus 32 --memory 65536 --disk 500
sudo minions host add node2 --address 10.0.1.2 --vcpus 64 --memory 131072 --disk 1000
sudo minions host list
sudo minions host status node1
sudo minions host remove node2
```

## Architecture

- **`minions`** — CLI + HTTP daemon that manages VM lifecycle, SSH gateway, and HTTPS proxy
- **`minions-agent`** — runs inside each VM, accepts commands over VSOCK (exec, status, network setup)
- **`minions-node`** — per-host agent for multi-host deployments
- **`minions-vsock-cli`** — low-level tool for debugging VSOCK communication

**How it works:**
- VMs boot from an Ubuntu rootfs with Cloud Hypervisor (direct `vmlinux` kernel boot, no bootloader)
- Each VM gets a TAP device on a bridge (`br0`) with NAT for internet access
- VM isolation via bridge port isolation (L2) and iptables rules (L3)
- Host ↔ guest communication over VSOCK
- LVM thin provisioning for instant copy-on-write VM creation
- SQLite for state tracking (VMs, IPs, snapshots, hosts)
- Wildcard DNS + Let's Encrypt for automatic HTTPS per VM

## Development

### Prerequisites (macOS cross-compilation)

```bash
brew install FiloSottile/musl-cross/musl-cross
rustup target add x86_64-unknown-linux-musl
```

### Build

```bash
mise run build     # cross-compile all binaries for Linux
mise run release   # build + create tarball in dist/
mise run clean     # remove build artifacts
```

### Publish a release

```bash
VERSION=v0.3.0 mise run publish
```

Creates a git tag, builds all binaries, and publishes a GitHub Release with the tarball attached.

### Deploy to server

```bash
# Upload a locally built binary for quick testing
scp target/x86_64-unknown-linux-musl/release/minions user@server:/tmp/
ssh user@server sudo install -m 0755 /tmp/minions /usr/local/bin/minions

# Or install from the latest GitHub release
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
```

## License

MIT
