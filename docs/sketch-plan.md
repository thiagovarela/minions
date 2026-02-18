# vmctl — VM-as-a-Service Platform

A service like exe.dev: instant VMs on the internet, accessible over HTTPS and SSH,
built on Cloud Hypervisor with direct rootfs (no Kata runtime layer).

Language: **Rust**

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  vmctl (single Rust binary — the control plane)                  │
│                                                                  │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────────┐    │
│  │ SSH        │  │ HTTPS      │  │ VM Lifecycle Manager     │    │
│  │ Gateway    │  │ Proxy      │  │ (users, quotas, state)   │    │
│  │ :22        │  │ :443       │  │                          │    │
│  └─────┬──────┘  └─────┬──────┘  └────────────┬────────────┘    │
│        │               │                       │                 │
│  ┌─────┴───────────────┴───────────────────────┴──────────────┐  │
│  │                    Cloud Hypervisor (per VM process)         │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │  │
│  │  │ VM 1     │  │ VM 2     │  │ VM 3     │  │ VM N     │   │  │
│  │  │ tap0     │  │ tap1     │  │ tap2     │  │ tapN     │   │  │
│  │  │ vsock    │  │ vsock    │  │ vsock    │  │ vsock    │   │  │
│  │  │ rootfs   │  │ rootfs   │  │ rootfs   │  │ rootfs   │   │  │
│  │  │ data disk│  │ data disk│  │ data disk│  │ data disk│   │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────┐  ┌────────────┐  ┌────────────────────────┐    │
│  │ br0 bridge  │  │ LVM thin   │  │ SQLite (state, users,  │    │
│  │ 10.0.0.0/16 │  │ pool       │  │  SSH keys, quotas)     │    │
│  └─────────────┘  └────────────┘  └────────────────────────┘    │
│                         Bare Metal Host                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## Core Design Decisions

### Direct rootfs (no Kata runtime)

One filesystem layer per VM. A Docker image is converted into an ext4 rootfs
at build time. The user boots into a normal Linux box with systemd, SSH, apt,
docker — everything just works. No container-inside-VM abstraction.

Kata's pieces we steal:
- Guest kernel config (`tools/packaging/kernel/`) — optimized for fast boot
- osbuilder approach (`tools/osbuilder/`) — for initial rootfs creation from Dockerfiles
- Cloud Hypervisor integration patterns (`src/runtime/virtcontainers/clh.go`) — as API reference

### VSOCK for host↔guest control

No network needed for the control channel. Cloud Hypervisor exposes a Unix
socket on the host that maps to VSOCK inside the guest. The guest agent listens
on a VSOCK port, the control plane connects via the Unix socket.

```
Host                                    Guest VM
vmctl ──► /run/vms/{name}.vsock ──►──► guest-agent (vsock port 1024)
```

### LVM thin provisioning for instant boot

Base rootfs image stored as an LVM thin volume. Each new VM gets a snapshot
(instant, copy-on-write, near-zero bytes until writes). Persistent data gets
a separate thin volume.

```
vg0/vmpool (thin pool, e.g. 500GB)
├── base-exeuntu          (golden image, ~4GB)
├── rootfs-alice-blog     (snapshot of base, COW)
├── rootfs-bob-api        (snapshot of base, COW)
├── data-alice-blog       (persistent disk, 10GB)
└── data-bob-api          (persistent disk, 25GB)
```

### One cloud-hypervisor process per VM

Each VM is a separate `cloud-hypervisor` process with its own API socket at
`/run/vms/{name}.sock`. The control plane manages these processes. If one
crashes, it only affects that VM.

---

## Components

### 1. Base Image Builder

Converts a Dockerfile into a bootable ext4 rootfs.

**Inputs:** Dockerfile (e.g. the `exeuntu`-equivalent base image)
**Outputs:** ext4 raw image written to an LVM thin volume

Steps:
1. `docker build` the Dockerfile
2. `docker export` the container filesystem
3. Inject the guest agent binary + systemd unit
4. Inject SSH host keys, cloud-init or custom first-boot config
5. Inject networking setup (static IP configured by agent on boot via VSOCK)
6. `mkfs.ext4 -d` to create the ext4 image
7. Write to `vg0/base-{imagename}` thin volume

Rebuild and re-snapshot when the base image changes. Running VMs keep their
existing rootfs; new VMs get the new base.

### 2. Guest Agent

A small Rust binary that runs inside each VM. Started by systemd on boot.

**Communication:** VSOCK (port 1024)
**Protocol:** Simple request/response, JSON or msgpack over length-prefixed frames

Responsibilities:
- Report readiness to the control plane on boot (health check)
- Configure networking (set IP, gateway, DNS — told by control plane via VSOCK)
- Execute commands (for the API/SSH gateway to proxy into)
- Report resource usage (CPU, memory, disk)
- Graceful shutdown handling

Does NOT handle:
- SSH (real sshd runs in the VM, gateway proxies to it)
- HTTP serving (user's own services, proxied by the HTTPS proxy)

Crates:
- `tokio` — async runtime
- `tokio-vsock` or `vsock` — VSOCK listener
- `serde` / `serde_json` — serialization
- `nix` — Linux syscalls for network config

### 3. VM Manager (core of vmctl)

Manages the full lifecycle of VMs.

**Create VM:**
1. Validate user quota (CPU, RAM, disk, VM count)
2. Generate VM name (or accept user-provided)
3. `lvcreate -s` snapshot base rootfs → `vg0/rootfs-{name}`
4. `lvcreate` persistent data disk → `vg0/data-{name}`
5. Create TAP device, attach to bridge, allocate IP from pool
6. Spawn `cloud-hypervisor --api-socket /run/vms/{name}.sock`
7. `PUT /api/v1/vm.create` with config (rootfs, data disk, TAP, VSOCK CID, CPUs, RAM)
8. `PUT /api/v1/vm.boot`
9. Wait for guest agent VSOCK connection
10. Tell agent to configure networking (IP, gateway, DNS)
11. Update state DB
12. Return VM info to user

**Delete VM:**
1. `PUT /api/v1/vm.shutdown` (graceful)
2. `PUT /api/v1/vmm.shutdown` (kill CH process)
3. Remove TAP device
4. `lvremove vg0/rootfs-{name}` and `vg0/data-{name}`
5. Free IP back to pool
6. Update state DB

**Other operations:** restart, resize (CH supports hot-add CPU/RAM), pause/resume,
snapshot (CH supports `vm.snapshot` while paused).

Crates:
- `hyper` / `reqwest` with Unix socket transport — CH API client
- `tokio::process` — spawning CH processes
- `rusqlite` — state DB
- `nix` — TAP/bridge/iptables management

### 4. Networking

**Host setup (one-time):**
```
bridge: br0, 10.0.0.1/16
NAT:    iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o eth0 -j MASQUERADE
```

**Per VM:**
```
TAP:    tap-{name}, attached to br0
VM IP:  allocated from 10.0.0.0/16 pool (stored in SQLite)
```

Cloud Hypervisor config for networking:
```json
{
  "net": [{
    "tap": "tap-myvm",
    "mac": "52:54:00:xx:xx:xx"
  }]
}
```

Guest agent configures the interface on boot:
```
ip addr add 10.0.0.42/16 dev enp0s3
ip link set enp0s3 up
ip route add default via 10.0.0.1
echo "nameserver 1.1.1.1" > /etc/resolv.conf
```

### 5. SSH Gateway

Custom SSH server on port 22 of the host.

**Two modes:**

1. **Command mode** — `ssh yourdomain.dev <command>`
   - Authenticate by public key → look up user in DB
   - `new [--image=X]` → create VM
   - `ls [--json]` → list VMs
   - `rm <name>` → delete VM
   - `restart <name>` → restart VM
   - `share <args>` → manage sharing

2. **Proxy mode** — `ssh {vmname}.yourdomain.xyz`
   - DNS wildcard `*.yourdomain.xyz` → host IP
   - Gateway looks up VM by name → finds internal IP
   - Proxies the SSH connection to the VM's sshd (port 22)

Crates:
- `russh` — SSH server and client (pure Rust, async, actively maintained)
- `rusqlite` — user/key lookups

### 6. HTTPS Reverse Proxy

Terminates TLS, routes to VMs by subdomain.

**Request flow:**
```
Client → https://myvm.yourdomain.xyz → Proxy (:443)
  → TLS terminate
  → Extract subdomain "myvm"
  → Look up VM internal IP (10.0.0.42)
  → Proxy to http://10.0.0.42:{port}
  → Inject headers: X-VmCtl-UserID, X-VmCtl-Email (if authenticated)
```

**TLS:**
- Wildcard cert for `*.yourdomain.xyz` via Let's Encrypt DNS-01 challenge
- Custom domains: per-domain certs via HTTP-01 challenge, stored on disk

**Auth:**
- Private VMs (default): redirect to login, set session cookie, then proxy
- Public VMs: proxy without auth, optionally inject headers if user is logged in

Crates:
- `hyper` — HTTP server + reverse proxy
- `rustls` — TLS termination
- `tokio` — async runtime
- `instant-acme` or `acme2` — Let's Encrypt ACME client

### 7. State & User Management

**SQLite database** (single file, no external deps, good enough for thousands of VMs).

Tables:
```sql
users (id, email, created_at)
ssh_keys (id, user_id, public_key, fingerprint, created_at)
vms (id, user_id, name, image, status, internal_ip, vsock_cid, ch_pid, created_at)
shares (id, vm_id, shared_with_email, share_type, created_at)
resource_quotas (user_id, max_vms, max_vcpus, max_ram_mb, max_disk_gb)
ip_pool (ip, vm_id, allocated_at)  -- or just derive from vms table
```

---

## Guest Kernel

Steal Kata's kernel config as a starting point. They maintain an optimized config
at `kata-containers/tools/packaging/kernel/configs/` that strips out everything
unnecessary for a cloud VM.

Key config options:
- `CONFIG_VIRTIO_*` — virtio drivers (net, blk, vsock, console)
- `CONFIG_EXT4_FS` — rootfs filesystem
- `CONFIG_VHOST_VSOCK` — VSOCK support (guest side)
- `CONFIG_NET_9P`, `CONFIG_9P_FS` — optional, for shared directories
- Disable: legacy hardware, sound, GPU, USB, most filesystems

Build once, ship the `vmlinux` binary with vmctl. Update occasionally.

---

## Cloud Hypervisor VM Config

Full config sent to `PUT /api/v1/vm.create`:

```json
{
  "cpus": {
    "boot_vcpus": 2,
    "max_vcpus": 4
  },
  "memory": {
    "size": 4294967296
  },
  "payload": {
    "kernel": "/opt/vmctl/vmlinux",
    "cmdline": "console=ttyS0 root=/dev/vda rw quiet"
  },
  "disks": [
    { "path": "/dev/vg0/rootfs-myvm" },
    { "path": "/dev/vg0/data-myvm" }
  ],
  "net": [
    { "tap": "tap-myvm", "mac": "52:54:00:ab:cd:ef" }
  ],
  "vsock": {
    "cid": 3,
    "socket": "/run/vms/myvm.vsock"
  },
  "rng": {
    "src": "/dev/urandom"
  },
  "serial": { "mode": "Null" },
  "console": { "mode": "Off" }
}
```

---

## Rust Crate Structure

```
vmctl/
├── Cargo.toml              (workspace)
├── crates/
│   ├── vmctl/              (main binary — CLI + orchestrator)
│   │   └── src/
│   │       ├── main.rs
│   │       ├── config.rs
│   │       └── db.rs
│   ├── vmctl-vmm/          (Cloud Hypervisor API client + process management)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── client.rs   (REST API over Unix socket)
│   │       ├── config.rs   (VmConfig builder)
│   │       └── process.rs  (spawn/monitor CH processes)
│   ├── vmctl-network/      (TAP, bridge, IP allocation)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── tap.rs
│   │       ├── bridge.rs
│   │       └── ip_pool.rs
│   ├── vmctl-storage/      (LVM thin provisioning)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── lvm.rs
│   │       └── rootfs.rs   (base image builder)
│   ├── vmctl-ssh/          (SSH gateway)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs
│   │       ├── commands.rs (new, ls, rm, etc.)
│   │       └── proxy.rs   (proxy mode to VMs)
│   ├── vmctl-proxy/        (HTTPS reverse proxy)
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs
│   │       ├── tls.rs
│   │       └── auth.rs
│   └── vmctl-agent/        (guest agent — separate binary, deployed inside VMs)
│       └── src/
│           ├── main.rs
│           ├── vsock.rs
│           ├── network.rs  (configure interfaces)
│           └── exec.rs     (run commands)
├── images/
│   └── base/
│       └── Dockerfile      (base VM image, like exeuntu)
└── kernel/
    └── config              (guest kernel .config, derived from Kata's)
```

---

## Key Rust Dependencies

```toml
# Async runtime
tokio = { version = "1", features = ["full"] }

# Cloud Hypervisor API client (HTTP over Unix socket)
hyper = { version = "1", features = ["client", "http1"] }
hyper-util = "0.1"
http-body-util = "0.1"
hyperlocal = "0.9"              # Unix socket HTTP transport

# SSH gateway
russh = "0.46"                  # SSH server + client
russh-keys = "0.46"             # Key parsing

# HTTPS proxy
rustls = "0.23"
tokio-rustls = "0.26"
instant-acme = "0.7"            # Let's Encrypt ACME

# Guest agent (VSOCK)
tokio-vsock = "0.5"             # async VSOCK for the agent
# Host side talks to CH's Unix socket, not VSOCK directly

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Database
rusqlite = { version = "0.32", features = ["bundled"] }

# Linux syscalls (TAP, bridge, iptables)
nix = { version = "0.29", features = ["net", "ioctl"] }
netlink-packet-route = "0.21"   # Netlink for network config
rtnetlink = "0.14"              # High-level netlink

# Utilities
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
```

---

## Build Order

### Phase 1: Prove it works (weekend)

On a bare metal box with KVM:
1. Install Cloud Hypervisor from pre-built binary
2. Build a guest kernel (clone Kata's kernel branch, use their config)
3. Build a base rootfs from a Dockerfile (`docker export` → `mkfs.ext4 -d`)
4. Boot it manually with `cloud-hypervisor` CLI
5. Verify: SSH into the VM, install packages, reboot, data persists

### Phase 2: Guest agent + VSOCK (1 week)

1. Write `vmctl-agent` — listens on VSOCK port 1024, configures networking,
   responds to health checks, executes commands
2. Bake agent into the base rootfs as a systemd service
3. From the host, connect to the CH VSOCK socket and talk to the agent
4. Verify: boot VM → agent comes up → host configures VM's IP via VSOCK

### Phase 3: VM manager (1-2 weeks)

1. Write `vmctl-vmm` — Rust client for CH REST API over Unix socket
2. Write `vmctl-network` — create/destroy TAP devices, manage IP pool
3. Write `vmctl-storage` — LVM thin snapshot creation/deletion
4. Wire it together in `vmctl` binary: `vmctl create myvm`, `vmctl destroy myvm`
5. Verify: single command creates a fully networked VM with persistent storage

### Phase 4: SSH gateway (1-2 weeks)

1. Write `vmctl-ssh` using `russh`
2. Command mode: `ssh yourdomain.dev new` → calls VM manager
3. Proxy mode: `ssh myvm.yourdomain.xyz` → proxies to VM's sshd
4. User registration: first SSH stores public key + email
5. Verify: full flow from `ssh yourdomain.dev new` to `ssh myvm.yourdomain.xyz`

### Phase 5: HTTPS proxy (1-2 weeks)

1. Write `vmctl-proxy` — wildcard TLS termination + reverse proxy
2. Auto-detect exposed port (parse Dockerfile EXPOSE or agent reports it)
3. Private/public toggle per VM
4. Auth header injection
5. Verify: `https://myvm.yourdomain.xyz` routes to VM's web server

### Phase 6: Polish (ongoing)

- Sharing (by email, by link, public)
- Custom domains with auto-TLS
- Resource quotas and billing (Stripe)
- VM snapshots and backups
- Multi-host (distribute VMs across multiple bare metal machines)
- Web dashboard
- Monitoring, alerting, log aggregation

---

## Hardware Requirements

**Minimum to start (single host):**
- Bare metal server: Hetzner AX42 (~€58/mo) — 8 cores, 64GB RAM, 2x512GB NVMe
- Or: OVH Advance-1 (~$65/mo), Equinix c3.small.x86 (~$0.50/hr)
- KVM-enabled (all dedicated servers are)
- Ubuntu 22.04+ or Debian 12+

**Host setup checklist:**
```bash
# Verify KVM
lsmod | grep kvm

# Install Cloud Hypervisor
wget https://github.com/cloud-hypervisor/cloud-hypervisor/releases/latest/download/cloud-hypervisor-static
chmod +x cloud-hypervisor-static
mv cloud-hypervisor-static /usr/local/bin/cloud-hypervisor

# Set up LVM thin pool on NVMe
pvcreate /dev/nvme1n1
vgcreate vg0 /dev/nvme1n1
lvcreate -L 400G --thinpool vmpool vg0

# Set up bridge + NAT
ip link add br0 type bridge
ip addr add 10.0.0.1/16 dev br0
ip link set br0 up
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o eth0 -j MASQUERADE

# DNS: wildcard A record *.yourdomain.xyz → host public IP
```

---

## Open Questions

- **VM hibernation/suspend**: Cloud Hypervisor supports pause/resume and snapshot/restore.
  Use this for idle VMs to pack more onto a host? Trade-off is resume latency.
- **Live migration**: CH supports `vm.send-migration` / `vm.receive-migration`.
  Needed for multi-host, but adds significant complexity.
- **Nested virtualization**: Users running Docker inside VMs need this.
  Works on KVM but adds overhead. Alternatively, use rootless containers
  (podman) which don't need nested virt.
- **GPU passthrough**: CH supports VFIO. Future feature for AI workloads.
- **Rate limiting / fair scheduling**: Multiple VMs sharing CPU — use cgroups
  on the CH processes? Or rely on the kernel scheduler?
