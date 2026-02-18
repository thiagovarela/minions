# Phase 6 — SSH Gateway

Phase 6 adds an SSH gateway that makes VMs accessible over SSH using your domain
(**MINICLANKERS.COM**) without needing to know each VM's internal IP.

Two modes run on a single port (22):

| Mode | Command | What it does |
|------|---------|--------------|
| **Command** | `ssh minions@ssh.miniclankers.com` | Manage VMs (ls, new, rm, …) |
| **Proxy** | `ssh vmname@ssh.miniclankers.com` | SSH directly into VM |

First-time users are prompted for an email address to register.

---

## 1. Cloudflare DNS Setup

Add these records in the Cloudflare dashboard for MINICLANKERS.COM:

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | `ssh` | `<your host IP>` | **DNS only** (grey cloud) |
| A | `@` | `<your host IP>` | DNS only |

> **Important**: keep the proxy **off** (grey cloud) for port 22 — Cloudflare
> doesn't proxy raw TCP/SSH traffic on arbitrary ports.

---

## 2. Host Setup

### 2a. Allow port 22 binding without root

The `minions` binary needs to listen on port 22. Two options:

**Option A — Run as root** (simplest, fine for a dedicated server):
```bash
sudo minions serve --bind 0.0.0.0:3000 --ssh-bind 0.0.0.0:22
```

**Option B — `CAP_NET_BIND_SERVICE` capability** (run as non-root):
```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/minions
# Now minions can bind port 22 as a normal user
minions serve --bind 0.0.0.0:3000 --ssh-bind 0.0.0.0:22
```

**Option C — Move host SSH to a different port** (if you SSH into the host itself):
```bash
# In /etc/ssh/sshd_config, change Port 22 → Port 2222, then:
sudo systemctl restart sshd
# Now port 22 is free for minions
sudo minions serve --bind 0.0.0.0:3000 --ssh-bind 0.0.0.0:22
```

### 2b. First run — key generation

On the first run with `--ssh-bind`, minions generates two key files:

| File | Purpose |
|------|---------|
| `/var/lib/minions/ssh_host_key` | SSH host key (identifies the gateway to clients) |
| `/var/lib/minions/proxy_key` | Private key used to authenticate to VMs |
| `/var/lib/minions/proxy_key.pub` | Public key injected into every new VM |

These are generated automatically — no manual step required.

### 2c. Systemd service update

Update `/etc/systemd/system/minions.service` to add `--ssh-bind`:

```ini
[Unit]
Description=minions VM daemon + SSH gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minions serve \
    --bind 0.0.0.0:3000 \
    --ssh-bind 0.0.0.0:22
Environment=MINIONS_API_KEY=your-secret-api-key
Environment=MINIONS_SSH_PUBKEY_PATH=/root/.ssh/authorized_keys
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart minions
sudo systemctl status minions
```

---

## 3. Build & Deploy

```bash
cd /tmp/minions
git pull origin main

# Cross-compile for the minipc (x86-64 Linux)
cargo build --release --target x86_64-unknown-linux-musl

# Copy to host
scp target/x86_64-unknown-linux-musl/release/minions root@<host>:/usr/local/bin/minions

# Restart daemon
ssh root@<host> systemctl restart minions
```

---

## 4. Usage

### Register (first time)

Connect interactively — the gateway prompts for your email:

```bash
ssh minions@ssh.miniclankers.com
# Welcome to MINICLANKERS.COM
#
# Enter your email to register: you@example.com
# ✓ Registered! Welcome, you@example.com.
# Type 'help' for available commands.
# $
```

### Manage VMs

```bash
# List VMs
ssh minions@ssh.miniclankers.com ls

# Create a VM (auto-named)
ssh minions@ssh.miniclankers.com new

# Create with specific name / resources
ssh minions@ssh.miniclankers.com new myapp --cpus 4 --mem 2048

# Destroy a VM
ssh minions@ssh.miniclankers.com rm myapp

# Restart
ssh minions@ssh.miniclankers.com restart myapp

# Copy
ssh minions@ssh.miniclankers.com cp myapp myapp-staging

# Rename (VM must be stopped)
ssh minions@ssh.miniclankers.com rename myapp production

# Who am I?
ssh minions@ssh.miniclankers.com whoami
```

### SSH into a VM

```bash
# Proxy mode: username = VM name
ssh myapp@ssh.miniclankers.com

# Run a single command
ssh myapp@ssh.miniclankers.com cat /etc/os-release
```

> The gateway authenticates to the VM using its **proxy key**
> (`/var/lib/minions/proxy_key`), which is automatically injected into every
> VM's `/root/.ssh/authorized_keys` at creation time.

### SSH config (optional, for convenience)

Add to `~/.ssh/config`:

```
Host ssh.miniclankers.com
    User minions
    IdentityFile ~/.ssh/id_ed25519

# Shortcut: ssh vm-myapp → ssh myapp@ssh.miniclankers.com
Host vm-*
    HostName ssh.miniclankers.com
    User %h
    IdentityFile ~/.ssh/id_ed25519
```

Then: `ssh vm-myapp` → proxied into VM `myapp`.

---

## 5. Architecture Notes

### Key injection flow

```
minions serve --ssh-bind 0.0.0.0:22
  │
  ├── Generate /var/lib/minions/proxy_key (if not exists)
  ├── Generate /var/lib/minions/proxy_key.pub
  │
  └── On VM create / copy:
        └── inject proxy_key.pub → VM /root/.ssh/authorized_keys (append)
```

### SSH routing

```
ssh minions@ssh.miniclankers.com ls
│
├── DNS: ssh.miniclankers.com → host IP
├── TCP connect to port 22
├── Authenticate by SSH public key
│   └── Look up fingerprint in users/ssh_keys DB table
│       ├── Found → authenticated user
│       └── Not found → registration prompt (collect email)
└── exec_request "ls"
    └── Call GET /api/vms (local HTTP API)
        └── Format + return output

ssh myapp@ssh.miniclankers.com
│
├── DNS: ssh.miniclankers.com → host IP (same)
├── TCP connect to port 22
├── Authenticate by SSH public key (same)
│   └── ssh_username = "myapp" ≠ "minions" → proxy mode
└── shell_request
    └── ConnectedVm::connect("10.0.0.x:22", proxy_key)
        └── authenticate as root with proxy_key
            └── Bidirectional channel bridge (tokio split stream)
```

### DB tables (new in phase 6)

```sql
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,   -- UUID v4
    email       TEXT UNIQUE NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,       -- openssh format
    fingerprint TEXT UNIQUE NOT NULL, -- SHA256 base64 (no padding)
    name        TEXT NOT NULL DEFAULT 'default',
    created_at  TEXT NOT NULL
);
```

Migration runs automatically on gateway startup — no manual DB changes needed.

---

## 6. Troubleshooting

### "proxy key rejected by VM"

The proxy key wasn't injected into this VM (it was created before phase 6).
Recreate the VM:

```bash
ssh minions@ssh.miniclankers.com rm oldvm
ssh minions@ssh.miniclankers.com new oldvm
```

Or inject manually via VSOCK agent:

```bash
cat /var/lib/minions/proxy_key.pub
sudo minions exec oldvm -- bash -c "echo '<key>' >> /root/.ssh/authorized_keys"
```

### "VM 'xyz' is stopped"

Start the VM first:

```bash
# Can't start from SSH yet (phase 7) — use HTTP API or CLI
minions --host http://localhost:3000 create xyz
```

### Host key changed warning

If you regenerate the host key (e.g., `/var/lib/minions/ssh_host_key`), clients
will see a "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED" message.
Remove the old entry:

```bash
ssh-keygen -R ssh.miniclankers.com
```
