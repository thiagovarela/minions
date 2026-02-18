# Phase 1: Boot a VM on Cloud Hypervisor

Reproduce the full setup from a fresh Ubuntu 24.04 host with KVM support.

**Tested on:** vps-2b1e18f2 (OVH KVM VPS) — Intel Core 6-core, 11GiB RAM, 96GB SSD, Ubuntu 25.04

---

## Prerequisites

- Bare metal (or nested-virt-enabled) Linux box with KVM
- Docker installed
- sudo access

Verify KVM is available:

```bash
lsmod | grep kvm
# Should show kvm_amd or kvm_intel
```

---

## 1. Install Cloud Hypervisor

```bash
sudo wget -O /usr/local/bin/cloud-hypervisor \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v50.0/cloud-hypervisor-static
sudo chmod +x /usr/local/bin/cloud-hypervisor
cloud-hypervisor --version
# cloud-hypervisor v50.0.0
```

Also install `ch-remote` (useful for controlling VMs):

```bash
sudo wget -O /usr/local/bin/ch-remote \
  https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v50.0/ch-remote-static
sudo chmod +x /usr/local/bin/ch-remote
```

---

## 2. Install dependencies

```bash
sudo apt install -y lvm2 build-essential flex bison libelf-dev libssl-dev bc sshpass
```

---

## 3. Create directory structure

```bash
sudo mkdir -p /var/lib/minions/{kernel,images,vms}
sudo mkdir -p /run/minions
sudo chown -R $(whoami):$(whoami) /var/lib/minions
```

---

## 4. Download the guest kernel

Cloud Hypervisor maintains a pre-built kernel optimized for VMs (stripped-down,
virtio drivers, fast boot). Built from their fork with `ch_defconfig`.

```bash
wget -O /var/lib/minions/kernel/vmlinux \
  https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.16.9-20251112/vmlinux-x86_64
```

This is an uncompressed `vmlinux` (~46MB). Cloud Hypervisor boots it directly
(no bootloader needed).

---

## 5. Build the base rootfs image

### 5a. Create the Dockerfile

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

# Enable SSH
RUN mkdir -p /run/sshd
RUN systemctl enable ssh

# SECURITY: Lock root password and disable password authentication
# SSH access is only via public key injected by the host
RUN passwd -l root
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
RUN sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Serial console for cloud-hypervisor
# NOTE: Serial console is enabled for debugging/troubleshooting via
# `minions logs <vmname>`. For production hardening, consider disabling
# autologin and requiring authentication.
RUN mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
RUN echo '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %I 115200 linux' \
    > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf
RUN systemctl enable serial-getty@ttyS0.service

# Set hostname
RUN echo 'minion' > /etc/hostname
EOF
```

### 5b. Build and export the container filesystem

```bash
cd ~/minions-build
docker build -t minions-base .
docker rm minions-export 2>/dev/null
docker create --name minions-export minions-base /bin/true
docker export minions-export > rootfs.tar
docker rm minions-export
```

### 5c. Create an ext4 image from the tarball

```bash
ROOTFS=/var/lib/minions/images/base-ubuntu.ext4

# Create a 2GB sparse file (only uses ~150MB on disk)
truncate -s 2G $ROOTFS
mkfs.ext4 -F -L rootfs $ROOTFS

# Mount and extract
sudo mkdir -p /tmp/minions-rootfs-mount
sudo mount -o loop $ROOTFS /tmp/minions-rootfs-mount
sudo tar xf ~/minions-build/rootfs.tar -C /tmp/minions-rootfs-mount
sudo umount /tmp/minions-rootfs-mount
sudo rmdir /tmp/minions-rootfs-mount
```

### 5d. Inject static network configuration

Inside the VM, the network interface appears as `eth0` (virtio-net). We use
systemd-networkd with a `Type=ether` match to configure it.

This step is done per-VM when creating a copy of the base image. Here we
show it for a VM with IP `10.0.0.2`:

```bash
VM_ROOTFS=/var/lib/minions/vms/test-vm-rootfs.ext4

# Copy the base image for this VM
cp /var/lib/minions/images/base-ubuntu.ext4 $VM_ROOTFS

# Mount and inject network config
sudo mkdir -p /tmp/minions-rootfs-mount
sudo mount -o loop $VM_ROOTFS /tmp/minions-rootfs-mount

sudo mkdir -p /tmp/minions-rootfs-mount/etc/systemd/network
sudo tee /tmp/minions-rootfs-mount/etc/systemd/network/10-vm.network > /dev/null << 'NETEOF'
[Match]
Type=ether

[Network]
Address=10.0.0.2/16
Gateway=10.0.0.1
DNS=1.1.1.1
NETEOF

# Enable systemd-networkd and resolved
sudo ln -sf /usr/lib/systemd/system/systemd-networkd.service \
    /tmp/minions-rootfs-mount/etc/systemd/system/multi-user.target.wants/systemd-networkd.service
sudo ln -sf /usr/lib/systemd/system/systemd-resolved.service \
    /tmp/minions-rootfs-mount/etc/systemd/system/multi-user.target.wants/systemd-resolved.service

# Fallback resolv.conf
sudo tee /tmp/minions-rootfs-mount/etc/resolv.conf > /dev/null << 'DNSEOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
DNSEOF

sudo umount /tmp/minions-rootfs-mount
sudo rmdir /tmp/minions-rootfs-mount
```

---

## 6. Set up host networking

### 6a. Create the bridge

```bash
sudo ip link add br0 type bridge
sudo ip addr add 10.0.0.1/16 dev br0
sudo ip link set br0 up
```

### 6b. Enable IP forwarding and NAT

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Find the main outbound interface
MAIN_IF=$(ip route show default | awk '{print $5}' | head -1)

# Masquerade VM traffic (outbound internet)
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o $MAIN_IF -j MASQUERADE

# Allow forwarding: VM → internet and internet → VM (established)
sudo iptables -I FORWARD -i br0 -o $MAIN_IF -j ACCEPT
sudo iptables -I FORWARD -i $MAIN_IF -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allow VM-to-VM traffic on the bridge (required when br_netfilter is loaded)
# br_netfilter routes intra-bridge traffic through the iptables FORWARD chain;
# without this rule, VMs on the same host cannot reach each other.
sudo iptables -I FORWARD -i br0 -o br0 -j ACCEPT
```

### 6c. Create a TAP device for the VM

One TAP device per VM, attached to the bridge.

```bash
sudo ip tuntap add dev tap-test mode tap
sudo ip link set tap-test master br0
sudo ip link set tap-test up
```

> **Note:** These network settings are not persistent across reboots.
> For production, configure them via systemd-networkd or netplan on the host.

---

## 7. Boot the VM

```bash
sudo cloud-hypervisor \
  --api-socket /run/minions/test-vm.sock \
  --kernel /var/lib/minions/kernel/vmlinux \
  --disk path=/var/lib/minions/vms/test-vm-rootfs.ext4 \
  --cpus boot=2 \
  --memory size=1024M \
  --net tap=tap-test,mac=52:54:00:00:00:02 \
  --serial tty \
  --console off \
  --cmdline 'console=ttyS0 root=/dev/vda rw quiet'
```

Run with `&` to background it, or in a separate terminal/tmux session.
The `--serial tty` flag prints the VM's serial console to stdout (useful for
debugging boot issues).

The VM boots in ~3 seconds to a systemd login prompt.

---

## 8. Verify

### Ping the VM

```bash
ping -c 3 10.0.0.2
```

### SSH into the VM

With the hardened base image, SSH requires a public key. The `minions` CLI
automatically injects your SSH public key during VM creation. For manual testing
at this stage, you would need to either:

1. Inject an SSH key via the VSOCK agent (Phase 2+), or
2. Access via serial console: `sudo minions logs <vmname>`

For development/testing only, you can temporarily enable password auth by
uncommenting the password lines in the Dockerfile above.

```bash
# After VM creation with minions (Phase 3+), SSH will work automatically:
ssh -o StrictHostKeyChecking=no root@10.0.0.2
```

### Inside the VM

```bash
hostname           # minion (or cloud-hypervisor)
uname -a           # Linux cloud-hypervisor 6.16.9+ ...
ip addr show       # eth0 with 10.0.0.2/16
free -h            # ~977Mi total
df -h /            # 2.0G disk, ~148M used
ping 1.1.1.1       # outbound internet works
apt-get update     # package repos reachable
curl ifconfig.me   # shows host's public IP
```

### Query VM status via Cloud Hypervisor API

```bash
sudo curl -s --unix-socket /run/minions/test-vm.sock \
  http://localhost/api/v1/vm.info | python3 -m json.tool
```

---

## 9. Shutdown the VM

```bash
# Graceful shutdown (tells the guest to power off)
sudo curl -s --unix-socket /run/minions/test-vm.sock \
  -X PUT http://localhost/api/v1/vm.power-button

# Or force kill the VMM process
sudo curl -s --unix-socket /run/minions/test-vm.sock \
  -X PUT http://localhost/api/v1/vmm.shutdown
```

---

## 10. Cleanup

```bash
# Remove TAP device
sudo ip link del tap-test

# Remove bridge (only if no VMs are using it)
sudo ip link set br0 down
sudo ip link del br0

# Remove iptables rules
MAIN_IF=$(ip route show default | awk '{print $5}' | head -1)
sudo iptables -t nat -D POSTROUTING -s 10.0.0.0/16 -o $MAIN_IF -j MASQUERADE
sudo iptables -D FORWARD -i br0 -o $MAIN_IF -j ACCEPT
sudo iptables -D FORWARD -i $MAIN_IF -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -D FORWARD -i br0 -o br0 -j ACCEPT

# Remove VM disk
rm /var/lib/minions/vms/test-vm-rootfs.ext4
```

---

## File layout after Phase 1

```
/usr/local/bin/
├── cloud-hypervisor                     # Cloud Hypervisor v50 static binary
└── ch-remote                            # CH remote control tool

/var/lib/minions/
├── kernel/
│   └── vmlinux                          # Guest kernel (46MB)
├── images/
│   └── base-ubuntu.ext4                 # Golden base image (2GB sparse, ~150MB actual)
└── vms/
    └── test-vm-rootfs.ext4              # Per-VM copy of the base image

/run/minions/
└── test-vm.sock                         # CH API socket (exists while VM is running)
```

---

## Key learnings

1. **Interface name inside VM is `eth0`**, not `enpXsY`. The CH virtio-net driver
   uses the classic naming. Use `Type=ether` in systemd-networkd to match reliably.

2. **Snap Docker can't access `/tmp`**. Build Dockerfiles from `$HOME` or another
   accessible directory.

3. **iptables FORWARD policy may be DROP** (e.g., Docker or Tailscale adds rules).
   Explicit ACCEPT rules for `br0 ↔ main interface` are needed for VM internet access.

4. **Sparse files work fine** for development. `truncate -s 2G` creates a 2GB file
   that only uses disk space for actual writes (~150MB for the base rootfs). For
   production, LVM thin provisioning gives instant COW snapshots.

5. **Cloud Hypervisor boots `vmlinux` directly** — no GRUB, no initramfs, no
   bootloader. The `--kernel` flag points straight at the uncompressed kernel binary.
   This is why boot is so fast (~3s to SSH-ready).
