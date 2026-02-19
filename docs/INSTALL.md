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

### Create the Dockerfile

```bash
mkdir -p ~/minions-build
cat > ~/minions-build/Dockerfile << 'EOF'
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd \
    systemd-sysv \
    openssh-server \
    iproute2 \
    iputils-ping \
    curl \
    ca-certificates \
    sudo \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd
RUN systemctl enable ssh

# SSH: key-based auth only
RUN passwd -l root
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
RUN sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Serial console for debugging (accessible via `minions logs`)
RUN mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
RUN echo '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %I 115200 linux' \
    > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
RUN systemctl enable serial-getty@ttyS0.service

RUN echo 'minion' > /etc/hostname
EOF
```

### Build and export

```bash
cd ~/minions-build
docker build -t minions-base .
docker create --name minions-export minions-base /bin/true
docker export minions-export > rootfs.tar
docker rm minions-export
```

### Create the ext4 image

```bash
sudo mkdir -p /var/lib/minions/images

ROOTFS=/var/lib/minions/images/base-ubuntu.ext4
truncate -s 2G $ROOTFS
mkfs.ext4 -F -L rootfs $ROOTFS

sudo mkdir -p /tmp/minions-rootfs-mount
sudo mount -o loop $ROOTFS /tmp/minions-rootfs-mount
sudo tar xf ~/minions-build/rootfs.tar -C /tmp/minions-rootfs-mount
sudo umount /tmp/minions-rootfs-mount
sudo rmdir /tmp/minions-rootfs-mount
```

## 6. Bake the agent into the image

```bash
sudo minions bake-agent
```

This injects the `minions-agent` binary and its systemd service into the base image so every VM starts with the agent running.

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
