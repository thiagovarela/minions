# Phase 4 — HTTP API + Daemon Mode

Phase 4 turns `minions` from a local-only CLI into a daemon with an HTTP REST API,
accessible remotely over Tailscale from any device.

**Tested on:** vps-2b1e18f2 (OVH KVM VPS) — Ubuntu 25.04

---

## What's New

| Feature | Description |
|---|---|
| `minions init` | One-command host setup (br0, iptables, dirs, systemd unit) |
| `minions serve` | HTTP API daemon on port 3000 |
| Startup reconciliation | Detects crashed VMs, cleans orphans on daemon start |
| Create rollback | Partial-create failures clean up TAP + rootfs + DB automatically |
| Remote CLI | `minions --host http://vps-2b1e18f2:3000 list` from your Mac |
| HTTP API | Full REST API for VMs — create, destroy, list, exec, status, logs |

---

## Deployment

### 1. Pull and bake

```bash
cd /tmp/minions && git pull origin main
sudo bash ./scripts/bake-agent.sh
```

### 2. One-time host setup

```bash
# Sets up br0, ip_forward, iptables, directories, systemd unit
sudo minions init

# Optional: persist networking across reboots
sudo minions init --persist
```

### 3. Start the daemon

```bash
sudo systemctl enable --now minions
sudo systemctl status minions
```

### 4. Verify

```bash
# Local
sudo minions list

# Remote (from Mac over Tailscale)
curl http://vps-2b1e18f2:3000/api/vms
```

---

## HTTP API Reference

Base URL: `http://vps-2b1e18f2:3000`

### Create a VM

```bash
curl -X POST http://vps-2b1e18f2:3000/api/vms \
  -H 'Content-Type: application/json' \
  -d '{"name":"myvm","cpus":2,"memory_mb":1024}'
```

```json
{
  "name": "myvm",
  "status": "running",
  "ip": "10.0.0.2",
  "vsock_cid": 3,
  "cpus": 2,
  "memory_mb": 1024,
  "pid": 12345,
  "created_at": "2026-02-18T10:00:00Z"
}
```

### List VMs

```bash
curl http://vps-2b1e18f2:3000/api/vms
```

### Get VM details

```bash
curl http://vps-2b1e18f2:3000/api/vms/myvm
```

### Execute a command

```bash
curl -X POST http://vps-2b1e18f2:3000/api/vms/myvm/exec \
  -H 'Content-Type: application/json' \
  -d '{"command":"uname","args":["-a"]}'
```

```json
{"exit_code":0,"stdout":"Linux cloud-hypervisor 6.16.9+...\n","stderr":""}
```

### Agent status

```bash
curl http://vps-2b1e18f2:3000/api/vms/myvm/status
```

### Serial console log

```bash
curl http://vps-2b1e18f2:3000/api/vms/myvm/logs
```

### Destroy a VM

```bash
curl -X DELETE http://vps-2b1e18f2:3000/api/vms/myvm
```

---

## Remote CLI

When `--host` is set, the CLI is a thin HTTP client — no sudo, no SSH into vps-2b1e18f2:

```bash
# From Mac
minions --host http://vps-2b1e18f2:3000 list
minions --host http://vps-2b1e18f2:3000 create myvm --cpus 4
minions --host http://vps-2b1e18f2:3000 exec myvm -- uname -a
minions --host http://vps-2b1e18f2:3000 destroy myvm
```

Auto-detect: if `--host` is omitted and a local daemon is running on
`127.0.0.1:3000`, the CLI uses it automatically (no sudo needed).

---

## Daemon Behaviour

### Startup Reconciliation

When `minions serve` starts, it:
1. Queries all VMs with non-stopped status from the DB
2. For each VM, checks if the `cloud-hypervisor` process (PID) is alive
3. Dead VMs → cleans TAP device + socket files → marks DB status `stopped`
4. Removes orphan socket files in `/run/minions/` with no DB entry

This handles: host reboots, OOM kills, crashed CH processes, partial creates.

### Create Rollback

If VM creation fails at any step (TAP create, CH spawn, agent timeout, network
config), all created resources are cleaned up automatically:
- CH process killed
- TAP device removed
- Rootfs directory deleted
- DB row removed

---

## Architecture

```
crates/minions/src/
├── main.rs       # CLI entry point — routes to remote/direct/daemon mode
├── api.rs        # axum HTTP routes
├── server.rs     # Daemon: startup reconciliation + HTTP server
├── client.rs     # reqwest HTTP client (CLI remote mode)
├── init.rs       # Host setup: bridge, iptables, dirs, systemd unit
├── vm.rs         # VM lifecycle (connection never held across .await)
├── hypervisor.rs # CH process management
├── network.rs    # TAP + bridge management
├── storage.rs    # Rootfs management
├── agent.rs      # VSOCK client
└── db.rs         # SQLite state
```

### Key Design Decision: No Connection Held Across `.await`

`rusqlite::Connection` is `Send` but not `Sync`, so `&Connection` cannot be
held across `.await` points in async handlers. All async VM functions (`create`,
`destroy`) open short-lived connections for each sync DB operation, dropping
them before any `await`.
