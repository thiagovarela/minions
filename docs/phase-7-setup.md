# Phase 7 — HTTPS Reverse Proxy

Phase 7 adds HTTP proxying for VM web services. Cloudflare handles TLS
(orange cloud / proxy mode); `minions` runs a plain HTTP proxy on port 80.

```
Browser → Cloudflare (TLS) → VPS port 80 (minions-proxy) → VM's web server
```

URLs follow the pattern: `https://<vmname>.miniclankers.com`

---

## 1. VPS / firewall

On a fresh VPS (future deployment), open port 80:

```bash
ufw allow 80/tcp
ufw allow 2222/tcp   # SSH gateway
ufw allow 3000/tcp   # only if you need direct API access; otherwise leave closed
```

---

## 2. Cloudflare DNS

Add these records (both **proxied** — orange cloud):

| Type | Name | Value |
|------|------|-------|
| A | `@` | `<VPS IP>` |
| A | `*` | `<VPS IP>` |

The wildcard `*` record makes every `<vmname>.miniclankers.com` resolve via
Cloudflare. Cloudflare's proxy terminates TLS; requests arrive at your VPS as
plain HTTP with the original `Host` header intact.

> **Note**: Cloudflare's free plan supports wildcard DNS, but wildcard
> certificates are not included. Since we're not managing TLS ourselves
> (Cloudflare does it), this is fine.

---

## 3. Systemd service

Update `/etc/systemd/system/minions.service`:

```ini
[Unit]
Description=Minions VM Manager Daemon + SSH Gateway + HTTP Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minions serve \
    --ssh-bind 0.0.0.0:2222 \
    --proxy-bind 0.0.0.0:80 \
    --domain miniclankers.com
Environment=MINIONS_API_KEY=<your-secret-key>
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
```

`MINIONS_API_KEY` is the password for private VMs' login page.

---

## 4. Usage

### Expose a VM's web server

Inside the VM, start a web server:

```bash
# e.g. a Python HTTP server on port 3000
python3 -m http.server 3000
```

Tell minions to proxy that port:

```bash
ssh -p 2222 minions@ssh.miniclankers.com expose myapp --port 3000
```

Then visit: `https://myapp.miniclankers.com`

The default port is **80** — if your VM's web server is on 80 you don't need
to run `expose`.

### Make a VM public (no login required)

By default all VM proxies require a password login. To make one public:

```bash
ssh -p 2222 minions@ssh.miniclankers.com set-public myapp
```

To require login again:

```bash
ssh -p 2222 minions@ssh.miniclankers.com set-private myapp
```

### `ls` output now shows proxy info

```
NAME         STATUS     IP               CPUS     MEMORY   PORT  ACCESS
---------------------------------------------------------------------------
myapp        running    10.0.0.2            2     1024 MiB  3000  public
api          running    10.0.0.3            4     2048 MiB    80  private
```

---

## 5. Private VM auth

Private VMs require login. The login page is at `/__minions/login`.

- **Password**: the value of `MINIONS_API_KEY`
- **Session**: 24-hour cookie (`minions_session`), in-memory (cleared on restart)
- **Logout**: visit `/__minions/logout`

---

## 6. Architecture

```
minions serve --proxy-bind 0.0.0.0:80 --domain miniclankers.com
│
├── axum HTTP server on 0.0.0.0:80
│   ├── /__minions/login   GET  → login HTML page
│   ├── /__minions/login   POST → validate password, set cookie, redirect
│   ├── /__minions/logout  GET  → clear cookie, redirect
│   └── /*                      → proxy handler
│       ├── Extract subdomain from Host header
│       ├── Look up VM in DB (get IP + proxy_port + proxy_public)
│       ├── If stopped → 503
│       ├── If private + no valid session → redirect to login
│       └── Forward request to http://{vm.ip}:{vm.proxy_port}
│
└── DB columns added to `vms`:
    proxy_port   INTEGER NOT NULL DEFAULT 80
    proxy_public INTEGER NOT NULL DEFAULT 0
```

### New API endpoints

| Method | Path | What it does |
|--------|------|-------------|
| `POST` | `/api/vms/{name}/expose` | `{"port": 3000}` — set proxy port |
| `POST` | `/api/vms/{name}/set-public` | Make VM publicly accessible |
| `POST` | `/api/vms/{name}/set-private` | Require auth to access |

---

## 7. Request body limit

The proxy currently collects the full request body before forwarding (32 MiB
limit). This is fine for typical web apps. Large file uploads (> 32 MiB) will
fail — streaming body forwarding is a Phase 7+ follow-up.

---

## 8. Troubleshooting

### 502 Bad Gateway

The VM's web server isn't running on the configured port. Check:

```bash
ssh -p 2222 testvm@ssh.miniclankers.com    # log into VM
ss -tlnp | grep 3000                        # is the server listening?
```

### 503 Service Unavailable

The VM is stopped. Start it:

```bash
ssh -p 2222 minions@ssh.miniclankers.com restart testvm
```

### Login loop

Session cookie is not being set. Check that Cloudflare isn't stripping
cookies — it shouldn't for the proxy mode. Also verify `MINIONS_API_KEY`
is set correctly.

### Cloudflare returning "Error 523: Origin unreachable"

Port 80 on the VPS is not listening or is blocked by a firewall. Check:

```bash
ss -tlnp | grep :80
ufw status
```
