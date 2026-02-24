# Installation

Full guide for setting up a Minions host from scratch on a bare-metal or KVM-enabled Linux server.

## Requirements

- Linux server with KVM support (bare-metal or nested virtualization enabled)
- Ubuntu 24.04+ recommended
- Root / sudo access

Verify KVM is available:

```bash
lsmod | grep kvm
# Should show kvm_amd or kvm_intel
```

## 1. Install Cloud Hypervisor

```bash
sudo wget -O /usr/local/bin/cloud-hypervisor \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v50.0/cloud-hypervisor-static
sudo chmod +x /usr/local/bin/cloud-hypervisor

sudo wget -O /usr/local/bin/ch-remote \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v50.0/ch-remote-static
sudo chmod +x /usr/local/bin/ch-remote

cloud-hypervisor --version
```

## 2. Install system dependencies

```bash
sudo apt install -y lvm2 build-essential flex bison libelf-dev libssl-dev bc docker.io
```

## 3. Install Minions binaries

```bash
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
```

Or install a specific version:

```bash
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash -s -- v0.2.0
```

This installs `minions`, `minions-agent`, `minions-node`, and `minions-vsock-cli` to `/usr/local/bin/`.

## 4. Download the guest kernel

Cloud Hypervisor boots an uncompressed `vmlinux` kernel directly — no bootloader or initramfs needed.

```bash
sudo mkdir -p /var/lib/minions/kernel
sudo wget -O /var/lib/minions/kernel/vmlinux \
  https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.16.9-20251112/vmlinux-x86_64
```

## 5. Build the base rootfs image

The base Ubuntu rootfs is built from `images/Dockerfile` in this repository. The Dockerfile includes:

- **Ubuntu 24.04 LTS** base image
- **System packages**: systemd, openssh-server, iproute2, iputils-ping, ca-certificates, sudo, dbus, dbus-user-session
- **Development tools**: git, curl, wget, vim, nano, htop, unzip, build-essential
- **SSH configuration**: key-based auth only, root login via SSH keys
- **Serial console** for debugging (accessible via `minions logs`)

To build the image, clone this repository and run:

```bash
git clone https://github.com/thiagovarela/minions.git
cd minions
sudo ./scripts/build-base-image.sh
```

This script automates the full Docker → ext4 pipeline:
1. Builds the Docker image from `images/Dockerfile`
2. Exports the container filesystem to a tarball
3. Creates a 2GB sparse ext4 image at `/var/lib/minions/images/base-ubuntu.ext4`
4. Mounts the image and extracts the tarball into it
5. Unmounts and cleans up

The script accepts an optional `--image-size` flag (default: `2G`):

```bash
sudo ./scripts/build-base-image.sh --image-size 4G
```

> **Note**: If you already have a base image, it will be backed up to `base-ubuntu.ext4.backup-<timestamp>` before being replaced.

## 6. Bake the agent into the image

After building the base image, inject the `minions-agent` binary and systemd service:

```bash
sudo ./scripts/bake-agent.sh
```

Or, if you've already installed the `minions` CLI:

```bash
sudo minions bake-agent
```

This mounts the base image and:
- Copies the `minions-agent` binary to `/usr/local/bin/minions-agent`
- Installs the `minions-agent.service` systemd unit
- Disables unnecessary getty services (saves ~13 MB RAM per VM)

After this step, every VM created with `minions create` will have the agent running from first boot.

## 7. Initialize the host

```bash
sudo minions init --persist
```

This sets up:
- Bridge network (`br0`) at `10.0.0.1/16`
- IP forwarding and NAT rules
- VM isolation (bridge port isolation + iptables)
- Directory structure (`/var/lib/minions/`, `/run/minions/`)
- Persistent networking across reboots

## 8. Verify

Create a test VM:

```bash
sudo minions create test
sudo minions list
sudo minions ssh test
sudo minions destroy test
```

## File layout

```
/usr/local/bin/
├── cloud-hypervisor          # Cloud Hypervisor VMM
├── ch-remote                 # CH remote control
├── minions                   # CLI + daemon
├── minions-agent             # Guest agent (also baked into image)
├── minions-node              # Per-host agent (multi-host)
└── minions-vsock-cli         # VSOCK debug tool

/var/lib/minions/
├── kernel/vmlinux            # Guest kernel (~46 MB)
├── images/base-ubuntu.ext4   # Base rootfs (2 GB sparse, ~150 MB actual)
├── vms/                      # Per-VM rootfs copies
└── minions.db                # SQLite state database

/run/minions/
└── *.sock                    # Cloud Hypervisor API sockets (per running VM)
```

## Updating

To update Minions binaries:

```bash
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
sudo minions bake-agent   # re-bake agent into base image if it changed
```

Existing VMs keep running. Only newly created VMs get the updated agent.
