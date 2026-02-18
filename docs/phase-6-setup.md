# Phase 6 — SSH Gateway

Phase 6 adds an SSH gateway that makes VMs accessible over SSH using your domain
(**MINICLANKERS.COM**) without needing to know each VM's internal IP.

Two modes run on a single port (default: **2222**):

| Mode | Command | What it does |
|------|---------|--------------|
| **Command** | `ssh -p 2222 minions@ssh.miniclankers.com` | Manage VMs (ls, new, rm, …) |
| **Proxy** | `ssh -p 2222 vmname@ssh.miniclankers.com` | SSH directly into VM |

The port is fully configurable via `--ssh-bind`. Use 2222 to avoid needing root
or `CAP_NET_BIND_SERVICE`. On a VPS, port 2222 is directly reachable — no NAT needed.

First-time users are prompted for an email address to register.

---

## 1. Cloudflare DNS Setup

Add these records in the Cloudflare dashboard for MINICLANKERS.COM:

| Type | Name  | Value           | Proxy                  |
|------|-------|-----------------|------------------------|
| A    | `ssh` | `54.37.17.133`  | **DNS only** (⚪ grey) |
| A    | `@`   | `54.37.17.133`  | Proxied (🟠 orange)    |
| A    | `*`   | `54.37.17.133`  | Proxied (🟠 orange)    |

> **`ssh` must be grey-cloud** — Cloudflare does not proxy raw TCP/SSH on port 2222.
> `@` and `*` stay orange-cloud for DDoS protection and CDN.

---

## 2. Host Setup

### 2a. VPS firewall

On a VPS, ports are directly reachable — no NAT or port-forwarding needed.
Ensure port 2222 is open:

```bash
ufw allow 2222/tcp   # SSH gateway
ufw allow 80/tcp     # HTTP (ACME challenges + redirect) — added in Phase 7
ufw allow 443/tcp    # HTTPS proxy — added in Phase 7
```

### 2b. First run — key generation

On the first run with `--ssh-bind`, minions generates two key files automatically:

| File | Purpose |
|------|---------|
| `/var/lib/minions/ssh_host_key` | SSH host key (identifies the gateway to clients) |
| `/var/lib/minions/proxy_key` | Private key used to authenticate to VMs |
| `/var/lib/minions/proxy_key.pub` | Public key injected into every new VM |

### 2c. Systemd service

`/etc/systemd/system/minions.service`:

```ini
[Unit]
Description=Minions VM Manager Daemon + SSH Gateway
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minions serve --ssh-bind 0.0.0.0:2222
Environment=MINIONS_SSH_PUBKEY_PATH=/root/.ssh/authorized_keys
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

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
sudo SUDO_USER=$(logname) bash ./scripts/bake-agent.sh
sudo systemctl restart minions
```

---

## 4. Usage

### Register (first time)

Connect interactively — the gateway prompts for your email:

```bash
ssh -p 2222 minions@ssh.miniclankers.com
# Welcome to MINICLANKERS.COM
#
# Enter your email to register: you@example.com
# ✓ Registered! Welcome, you@example.com.
# Type 'help' for available commands.
# $
```

### SSH config (recommended)

Add to `~/.ssh/config`:

```
Host ssh.miniclankers.com
    Port 2222
    User minions
    IdentityFile ~/.ssh/id_ed25519
```

After this, no need to type `-p 2222` or `-l minions`:

```bash
ssh ssh.miniclankers.com ls
ssh ssh.miniclankers.com new myapp --cpus 4 --mem 2048
ssh ssh.miniclankers.com whoami
```

For VM proxy access, add a wildcard entry:

```
# Any *.miniclankers.com → gateway at port 2222, username = hostname prefix
Host *.miniclankers.com
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
```

Then:

```bash
# SSH into VM "myapp" (username = VM name)
ssh myapp@ssh.miniclankers.com

# Or with the wildcard entry above, if DNS points subdomains to the host:
# ssh myapp.miniclankers.com
```

### Manage VMs

```bash
# List VMs
ssh -p 2222 minions@ssh.miniclankers.com ls

# Create a VM
ssh -p 2222 minions@ssh.miniclankers.com new
ssh -p 2222 minions@ssh.miniclankers.com new myapp --cpus 4 --mem 2048

# Destroy
ssh -p 2222 minions@ssh.miniclankers.com rm myapp

# Stop / restart / rename / copy
ssh -p 2222 minions@ssh.miniclankers.com stop myapp
ssh -p 2222 minions@ssh.miniclankers.com restart myapp
ssh -p 2222 minions@ssh.miniclankers.com rename myapp production
ssh -p 2222 minions@ssh.miniclankers.com cp myapp myapp-staging

# Account info
ssh -p 2222 minions@ssh.miniclankers.com whoami
ssh -p 2222 minions@ssh.miniclankers.com ssh-key list
```

### SSH into a VM

```bash
# username = VM name, gateway proxies to VM's sshd
ssh -p 2222 testvm@ssh.miniclankers.com

# Run a single command
ssh -p 2222 testvm@ssh.miniclankers.com cat /etc/os-release
```

> The gateway authenticates to the VM using its **proxy key**
> (`/var/lib/minions/proxy_key`), which is automatically injected into every
> VM's `/root/.ssh/authorized_keys` at creation time.

---

## 5. Architecture Notes

### Key injection flow

```
minions serve --ssh-bind 0.0.0.0:2222
  │
  ├── Generate /var/lib/minions/ssh_host_key  (if not exists)
  ├── Generate /var/lib/minions/proxy_key[.pub] (if not exists)
  │
  └── On VM create / copy:
        └── inject proxy_key.pub → VM /root/.ssh/authorized_keys (append)
```

### SSH routing

```
ssh -p 2222 minions@ssh.miniclankers.com ls
│
├── DNS: ssh.miniclankers.com → 54.37.17.133 (grey cloud, direct)
├── TCP connect to minions gateway on port 2222
├── Authenticate by SSH public key fingerprint → users/ssh_keys DB table
│   ├── Known key → authenticated user
│   └── Unknown key → registration prompt (collect email)
└── exec_request "ls" → GET /api/vms (local HTTP API) → format output

ssh -p 2222 myapp@ssh.miniclankers.com
│
└── ssh_username = "myapp" ≠ "minions" → proxy mode
    └── ConnectedVm::connect("10.0.0.x:22", proxy_key)
        └── Bidirectional bridge (tokio::io::split on ChannelStream)
```

### DB tables (new in phase 6)

```sql
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    fingerprint TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL DEFAULT 'default',
    created_at  TEXT NOT NULL
);
```

Migration runs automatically on gateway startup.

---

## 6. Troubleshooting

### "proxy key rejected by VM"

The proxy key wasn't injected (VM was created before phase 6).
Recreate the VM:

```bash
ssh -p 2222 minions@ssh.miniclankers.com rm oldvm
ssh -p 2222 minions@ssh.miniclankers.com new oldvm
```

Or inject manually:

```bash
cat /var/lib/minions/proxy_key.pub
sudo minions exec oldvm -- bash -c "echo '<key>' >> /root/.ssh/authorized_keys"
```

### "VM 'xyz' is stopped"

Start the VM first via the HTTP API or CLI:

```bash
minions --host http://vps-2b1e18f2:3000 create xyz
```

### Host key changed warning

If you regenerate the host key, remove the old client-side entry:

```bash
ssh-keygen -R '[ssh.miniclankers.com]:2222'
```

### Port 2222 not reachable

Ensure `ufw allow 2222/tcp` has been applied on the VPS.
On vps-2b1e18f2:

```bash
ss -tlnp | grep 2222   # should show minions listening
```
