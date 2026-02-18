# Phase 5 — VM Lifecycle Completions

Phase 5 rounds out the basic VM lifecycle with `restart`, `rename`, `cp`, and a
`--json` output flag.  No new runtime dependencies or infra changes are required
— all additions live inside the existing `minions` binary.

---

## What's New

| Feature | Command | API endpoint |
|---------|---------|--------------|
| VM restart | `minions restart <name>` | `POST /api/vms/{name}/restart` |
| VM rename  | `minions rename <old> <new>` | `POST /api/vms/{name}/rename` |
| VM copy    | `minions cp <source> [new-name]` | `POST /api/vms/{name}/copy` |
| JSON output | `--json` (global flag) | all endpoints already return JSON |

---

## Upgrade

Pull and rebuild:

```bash
cd /tmp/minions && git pull origin main
sudo bash ./scripts/bake-agent.sh   # rebuilds + installs /usr/local/bin/minions
sudo systemctl restart minions       # reload daemon
```

---

## Usage

### VM Restart

Sends an ACPI reboot signal to the guest via Cloud Hypervisor.  The VMM
process stays alive; the guest OS performs a clean reboot.  The VM will be
briefly unreachable over SSH / VSOCK while the guest boots.

```bash
# Direct (local)
sudo minions restart myvm

# Remote
minions --host http://minipc:3000 restart myvm

# JSON output
sudo minions --json restart myvm
```

```json
{
  "name": "myvm",
  "status": "running",
  "ip": "10.0.0.2",
  "cpus": 2,
  "memory_mb": 1024,
  "pid": 12345
}
```

**Rules:**
- VM must be in `running` state.  Returns an error for stopped/creating VMs.
- If the CH API call fails (e.g. VMM crashed), the status is restored to `running`
  and the error is returned to the caller.

### VM Rename

Renames a stopped VM.  The filesystem directory, TAP device, and all DB columns
are updated atomically.

```bash
# VM must be stopped first
sudo minions destroy myvm   # or wait for it to stop

# Then rename
sudo minions rename myvm production-api

# Or via API
curl -X POST http://minipc:3000/api/vms/myvm/rename \
  -H 'Content-Type: application/json' \
  -d '{"new_name": "production-api"}'
```

**Rules:**
- Source VM must exist.
- Source VM must be in `stopped` state.  Renaming a running VM would leave
  socket paths and TAP device names out of sync.
- Destination name must not already exist.
- Name validation applies (≤ 11 chars, alphanumeric + hyphens).

### VM Copy

Creates an independent VM from a copy of an existing VM's rootfs.  The source
may be running or stopped.  The copy gets a fresh IP, VSOCK CID, TAP device,
and boots normally.

```bash
# Copy with auto-generated name (source + "-copy" suffix)
sudo minions cp myvm

# Copy with explicit name
sudo minions cp myvm myvm-staging

# Remote
minions --host http://minipc:3000 cp myvm myvm-staging

# JSON output
sudo minions --json cp myvm
```

```json
{
  "name": "myvm-copy",
  "status": "running",
  "ip": "10.0.0.3",
  "cpus": 2,
  "memory_mb": 1024,
  "pid": 12399
}
```

**Rules:**
- Source VM must exist (but may be running or stopped).
- The copy inherits the source's CPU and memory config.
- Rootfs is copied with `cp --sparse=always` — fast and space-efficient.
- The copy gets a fresh SSH authorized_keys from the host user's key (same as `create`).
- If boot fails, all resources (TAP, rootfs copy, DB row) are cleaned up.

**Auto-generated name:** if no name is supplied, the copy is named
`{source_prefix}-copy` where `source_prefix` is the first 6 chars of the
source name (to stay within the 11-char TAP limit).

### JSON Output (`--json`)

Add `--json` anywhere in the command line to receive machine-readable output.

```bash
# List as JSON array
sudo minions --json list

# Single VM as JSON object
sudo minions --json create myvm
sudo minions --json restart myvm

# Destructive operations return a message object
sudo minions --json destroy myvm
sudo minions --json rename myvm newname
```

**`list` output:**
```json
[
  {
    "name": "myvm",
    "status": "running",
    "ip": "10.0.0.2",
    "cpus": 2,
    "memory_mb": 1024,
    "pid": 12345
  }
]
```

**Destructive operation output:**
```json
{ "message": "VM 'myvm' destroyed" }
```

---

## API Reference

All new endpoints require the same bearer-token auth as existing ones.

### `POST /api/vms/{name}/restart`

No request body required.

**Response:** `200 OK` — VM object  
**Errors:** `404` not found, `500` CH API failure

### `POST /api/vms/{name}/rename`

```json
{ "new_name": "production-api" }
```

**Response:** `200 OK`
```json
{ "message": "VM 'myvm' renamed to 'production-api'" }
```
**Errors:** `404` not found, `400` not stopped / name conflict / invalid name

### `POST /api/vms/{name}/copy`

```json
{ "new_name": "myvm-staging" }
```

**Response:** `201 Created` — new VM object  
**Errors:** `404` source not found, `400` destination already exists / invalid name

---

## Architecture Notes

### `hypervisor::reboot()`

Uses the CH REST API endpoint `PUT /api/v1/vm.reboot`.  Cloud Hypervisor sends
an ACPI reset to the guest; the VMM process does **not** restart.  This is the
fastest possible reboot path — no process respawn, no rootfs re-copy, no VSOCK
re-handshake required (VSOCK CID stays the same).

### `vm::rename()`

Steps:
1. Validate new name (≤ 11 chars, alphanumeric + hyphens)
2. Check source exists + is stopped
3. Check destination doesn't exist
4. `mv` the rootfs directory (`VMS_DIR/{old}` → `VMS_DIR/{new}`)
5. `ip link set tap-{old} name tap-{new}` (best-effort)
6. Update DB: name, tap_device, ch_api_socket, ch_vsock_socket, rootfs_path

### `vm::copy()`

Identical to `vm::create()` except step 3 uses `cp --sparse=always` from the
source VM's rootfs instead of the base image.  The agent is re-contacted to
configure a new IP; SSH keys are re-injected from the host user's public key.
