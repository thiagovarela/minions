# Phase 2: Guest Agent + VSOCK Communication

Building on Phase 1, we now have a guest agent that runs inside VMs and communicates with the host over VSOCK. The agent handles network configuration, health checks, command execution, and status reporting — all without needing to edit the rootfs for each VM.

**Tested on:** vps-2b1e18f2 (OVH KVM VPS) — Ubuntu 25.04

---

## What Changed

### Phase 1 → Phase 2

| Phase 1 | Phase 2 |
|---------|---------|
| Static network config baked into rootfs | Agent configures network dynamically via VSOCK |
| No host↔guest control channel | Full JSON-RPC over VSOCK |
| Edit rootfs to change anything | Send commands from host to running VM |

### Architecture

```
Host                                          Guest VM
─────────────────────────────────────         ─────────────────────────
minions-host CLI                              minions-agent (systemd service)
    │                                            │
    └──► /run/minions/{vm}.vsock ─────────────► VsockListener (port 1024)
         (Unix socket)                           │
                                                 ├─ configure_network
         "CONNECT 1024\n"                        ├─ health_check
         ◄─ "OK <port>\n"                        ├─ exec
         ◄──── JSON frames ────►                 └─ report_status
```

### Components

**3 Rust crates:**

- **`minions-proto`** — Shared protocol types (Request, Response) + frame codec (length-prefixed JSON)
- **`minions-agent`** — Guest binary, runs inside VM, listens on VSOCK port 1024
- **`minions-host`** — Host CLI for testing agent communication (later absorbed into main `minions` CLI)

---

## Prerequisites

Same as Phase 1, plus:
- Rust toolchain on vps-2b1e18f2 (for building)
- `git` to clone the minions repo

---

## Build

On `vps-2b1e18f2`:

```bash
cd /tmp
git clone git@github.com:thiagovarela/minions.git
cd minions
source ~/.cargo/env
cargo build --release -p minions-agent -p minions-host
```

Binaries:
- `/tmp/minions/target/release/minions-agent` (~1.7MB)
- `/tmp/minions/target/release/minions-host` (~3MB)

---

## Deploy the Agent into the VM Rootfs

```bash
# Copy agent binary
cp /tmp/minions/target/release/minions-agent /var/lib/minions/minions-agent
chmod +x /var/lib/minions/minions-agent

# Create a fresh VM rootfs image
cp /var/lib/minions/images/base-ubuntu.ext4 /var/lib/minions/vms/agent-test-vm.ext4

# Mount the rootfs
sudo mkdir -p /tmp/minions-rootfs-mount
sudo mount -o loop /var/lib/minions/vms/agent-test-vm.ext4 /tmp/minions-rootfs-mount

# Inject agent binary
sudo cp /var/lib/minions/minions-agent /tmp/minions-rootfs-mount/usr/local/bin/
sudo chmod +x /tmp/minions-rootfs-mount/usr/local/bin/minions-agent

# Create systemd unit
sudo tee /tmp/minions-rootfs-mount/etc/systemd/system/minions-agent.service > /dev/null << 'EOF'
[Unit]
Description=Minions Guest Agent
After=systemd-modules-load.service
Wants=systemd-modules-load.service

[Service]
Type=simple
ExecStart=/usr/local/bin/minions-agent
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
sudo ln -sf /etc/systemd/system/minions-agent.service \
    /tmp/minions-rootfs-mount/etc/systemd/system/multi-user.target.wants/minions-agent.service

# Remove Phase 1's static network config (agent handles networking now)
sudo rm -f /tmp/minions-rootfs-mount/etc/systemd/network/10-vm.network
sudo rm -f /tmp/minions-rootfs-mount/etc/systemd/system/vm-network.service
sudo rm -f /tmp/minions-rootfs-mount/etc/systemd/system/multi-user.target.wants/vm-network.service

# Unmount
sudo umount /tmp/minions-rootfs-mount
```

---

## Boot a VM with VSOCK

```bash
# Clean up any existing test VM
sudo pkill -f 'cloud-hypervisor.*agent-test-vm' || true
sudo ip link del tap-test 2>/dev/null || true

# Create TAP device (if not already present)
sudo ip tuntap add dev tap-test mode tap
sudo ip link set tap-test master br0
sudo ip link set tap-test up

# Boot with VSOCK
sudo cloud-hypervisor \
  --api-socket /run/minions/agent-test-vm.sock \
  --kernel /var/lib/minions/kernel/vmlinux \
  --disk path=/var/lib/minions/vms/agent-test-vm.ext4 \
  --cpus boot=2 \
  --memory size=1024M \
  --net tap=tap-test,mac=52:54:00:00:00:03 \
  --vsock cid=3,socket=/run/minions/agent-test-vm.vsock \
  --serial tty \
  --console off \
  --cmdline 'console=ttyS0 root=/dev/vda rw quiet' \
  &>/tmp/agent-test-vm.log &
```

**Key change:** `--vsock cid=3,socket=/run/minions/agent-test-vm.vsock`

This creates a Unix socket at `/run/minions/agent-test-vm.vsock` that the host uses to talk to the guest.

---

## Verify

### Check the agent started

```bash
tail -30 /tmp/agent-test-vm.log | grep minions-agent
```

You should see:
```
[  OK  ] Started minions-agent.service - Minions Guest Agent.
```

### Health check

```bash
sudo /tmp/minions/target/release/minions-host \
  --socket /run/minions/agent-test-vm.vsock \
  health
```

Output:
```json
{
  "status": "ok",
  "uptime_secs": 17,
  "hostname": "cloud-hypervisor"
}
```

### Configure networking

```bash
sudo /tmp/minions/target/release/minions-host \
  --socket /run/minions/agent-test-vm.vsock \
  configure-network \
  --ip 10.0.0.2/16 \
  --gateway 10.0.0.1 \
  --dns 1.1.1.1,8.8.8.8
```

Output:
```json
{
  "status": "ok",
  "message": "network configured"
}
```

### Test internet from inside the VM

```bash
sudo /tmp/minions/target/release/minions-host \
  --socket /run/minions/agent-test-vm.vsock \
  exec -- ping -c 3 1.1.1.1
```

Output:
```json
{
  "status": "ok",
  "exit_code": 0,
  "stdout": "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=3.54 ms\n...",
  "stderr": ""
}
```

### Report system status

```bash
sudo /tmp/minions/target/release/minions-host \
  --socket /run/minions/agent-test-vm.vsock \
  status
```

Output:
```json
{
  "status": "ok",
  "uptime_secs": 45,
  "memory_total_mb": 977,
  "memory_used_mb": 126,
  "disk_total_gb": 1,
  "disk_used_gb": 0
}
```

---

## Protocol Details

### VSOCK Handshake (Cloud Hypervisor / Firecracker)

1. **Host connects** to the Unix socket (`/run/minions/{vm}.vsock`)
2. **Host sends:** `CONNECT 1024\n` (1024 is the VSOCK port the agent listens on)
3. **CH responds:** `OK <assigned_hostside_port>\n`
4. **Bidirectional stream** established — host and guest can now exchange data

### Message Format

Length-prefixed JSON frames:
- 4 bytes: message length (u32 big-endian)
- N bytes: JSON payload

### Request Types

```json
// Health check
{"type": "health_check"}

// Configure network
{"type": "configure_network", "ip": "10.0.0.2/16", "gateway": "10.0.0.1", "dns": ["1.1.1.1"]}

// Execute command
{"type": "exec", "command": "ping", "args": ["-c", "3", "1.1.1.1"]}

// Report status
{"type": "report_status"}
```

### Response Format

```json
// Success
{"status": "ok", "message": "...", ...}

// Error
{"status": "error", "message": "..."}
```

---

## Key Learnings

1. **VSOCK port 1024** — Guest listens on `VMADDR_CID_ANY:1024`. Host connects via Unix socket + `CONNECT 1024\n` handshake.

2. **Agent must start before network config** — Systemd unit has `After=systemd-modules-load.service` to ensure `/dev/vsock` exists.

3. **No network until agent configures it** — The VM has no network connectivity until the host sends `configure_network`. This is intentional — each VM gets its IP dynamically from the orchestrator (Phase 3).

4. **exec requires `--` separator** — When using `minions-host exec`, pass `--` before command args to avoid clap flag parsing issues:
   ```bash
   minions-host exec -- ping -c 3 1.1.1.1
   ```

5. **Guest kernel needs `CONFIG_VIRTIO_VSOCKETS`** — The Cloud Hypervisor pre-built kernel already has this. Verify with `ls /dev/vsock` inside the VM.

6. **Native build on vps-2b1e18f2** — Cross-compiling from macOS with zig ran into CRT linking conflicts. Building natively on the target platform (x86_64 Linux) is simpler and faster for this project.

---

## Next Steps (Phase 3)

- **VM Manager** — Orchestrate full lifecycle: create, destroy, list VMs
- **`minions` CLI** — Unified interface (`minions create`, `minions ssh`, `minions logs`)
- **Automatic IP allocation** — Pool management (10.0.0.2 - 10.0.255.254)
- **SQLite state DB** — Track VMs, users, IPs, quotas
- **Systemd integration** — Restart VMs on host reboot

---

## Files

| Path | Description |
|------|-------------|
| `/var/lib/minions/minions-agent` | Agent binary (1.7MB) |
| `/var/lib/minions/vms/agent-test-vm.ext4` | VM rootfs with agent baked in |
| `/run/minions/agent-test-vm.vsock` | VSOCK Unix socket (created by Cloud Hypervisor) |
| `/tmp/minions/target/release/minions-host` | Host CLI for testing |
| `/tmp/agent-test-vm.log` | VM serial console output |
