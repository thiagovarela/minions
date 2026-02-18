# Phase 7 — Native TLS Termination

Phase 7 replaces the Cloudflare Flexible/plain-HTTP setup with native TLS on the origin.
`minions-proxy` now terminates TLS itself on port 443 using rustls.

```
Browser → Cloudflare (Full mode) → VPS:443 (rustls, Cloudflare Origin Cert) → VM
Browser → VPS:80 → 301 redirect to HTTPS (ACME HTTP-01 challenges for custom domains)
```

**SSL/TLS mode in Cloudflare:** set to **Full** (or Full strict with a Cloudflare Origin Cert).

URLs follow the same pattern: `https://<vmname>.miniclankers.com`

---

## Why not "Flexible" mode?

Cloudflare Flexible proxies HTTPS for the browser but connects to the origin over plain
HTTP. This means:
- Traffic inside the datacenter between Cloudflare and the VPS is unencrypted.
- Session cookies arrive over HTTP — browsers won't set the `Secure` flag properly.

**Full** mode: Cloudflare connects to the origin over HTTPS. The origin cert only needs to be
trusted by Cloudflare (not browsers), so a **Cloudflare Origin Certificate** is the right tool —
free, zero-renewal (up to 15 years), and doesn't require any ACME challenge.

---

## Architecture

```
*.miniclankers.com (orange cloud, Cloudflare Full mode)
  Browser ──► Cloudflare edge ──► VPS:443 (Cloudflare Origin Cert) ──► VM

custom.example.com (grey cloud / DNS only, direct TLS)
  Browser ──► VPS:443 (Let's Encrypt cert) ──► VM

VPS:80 ──► 301 Location: https://... (+ serves ACME HTTP-01 challenge tokens)
```

---

## 1. Cloudflare SSL/TLS settings

In the Cloudflare dashboard → **SSL/TLS** → **Overview**:
- Set mode to **Full** (or **Full (strict)**)

In **SSL/TLS** → **Origin Server**:
- Click **Create Certificate**
- Key type: RSA 2048
- Hostnames: `miniclankers.com`, `*.miniclankers.com`
- Validity: 15 years (maximum)
- Click **Create** — download `fullchain.pem` (certificate) and `privkey.pem` (key)

> **Full vs Full (strict):** A Cloudflare Origin Certificate is trusted for Full strict.
> Let's Encrypt certs also work for Full strict. Self-signed certs only work for Full (not strict).

---

## 2. DNS records (grey cloud for SSH + apex)

In Cloudflare DNS:

| Type | Name | Value            | Proxy status  |
|------|------|------------------|---------------|
| A    | `@`  | `54.37.17.133`   | Proxied (🟠)  |
| A    | `*`  | `54.37.17.133`   | Proxied (🟠)  |
| A    | `ssh`| `54.37.17.133`   | DNS only (⚪)  |

> `ssh.miniclankers.com` must be grey-cloud — Cloudflare does not proxy raw TCP/SSH.
> `@` and `*` stay orange-cloud so Cloudflare provides DDoS protection and CDN.

---

## 3. Install cert on VPS

```bash
# Create cert directory for the wildcard
sudo mkdir -p /var/lib/minions/certs/'*.miniclankers.com'

# Paste the certificate content from Cloudflare
sudo tee /var/lib/minions/certs/'*.miniclankers.com'/fullchain.pem << 'EOF'
<paste Cloudflare Origin Certificate here>
EOF

# Paste the private key content from Cloudflare
sudo tee /var/lib/minions/certs/'*.miniclankers.com'/privkey.pem << 'EOF'
<paste private key here>
EOF

sudo chmod 600 /var/lib/minions/certs/'*.miniclankers.com'/privkey.pem
```

Verify it loaded correctly:
```bash
openssl x509 -in /var/lib/minions/certs/'*.miniclankers.com'/fullchain.pem -noout -subject -dates
```

---

## 4. Firewall

```bash
ufw allow 443/tcp    # HTTPS proxy
ufw allow 80/tcp     # ACME challenges + redirect
ufw allow 2222/tcp   # SSH gateway
# port 3000 (API) stays closed — internal only
```

---

## 5. Environment file

`/etc/minions/env` on vps-2b1e18f2:

```env
MINIONS_API_KEY=<your-secret-key>
MINIONS_SSH_PUBKEY_PATH=/root/.ssh/authorized_keys
# Required for DNS-01 wildcard cert provisioning (custom domains use HTTP-01)
# MINIONS_CF_DNS_TOKEN=<cloudflare-dns-api-token-with-Zone:DNS:Edit>
```

---

## 6. Systemd service

`/etc/systemd/system/minions.service` on vps-2b1e18f2:

```ini
[Unit]
Description=Minions VM Manager Daemon + SSH Gateway + HTTPS Proxy
After=network-online.target systemd-networkd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minions serve \
    --ssh-bind 0.0.0.0:2222 \
    --proxy-bind 0.0.0.0:443 \
    --http-bind 0.0.0.0:80 \
    --domain miniclankers.com \
    --public-ip 54.37.17.133 \
    --acme-email admin@miniclankers.com
EnvironmentFile=-/etc/minions/env
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
sudo journalctl -u minions -f
```

---

## 7. Deploy updated binary

```bash
# On vps-2b1e18f2 — pull, rebuild, bake agent, restart
cd /tmp/minions
git pull origin main
sudo bash ./scripts/bake-agent.sh
sudo systemctl restart minions
```

---

## 8. Verify

```bash
# HTTPS proxy is live
curl -I https://miniclankers.com

# SSH gateway responds
ssh -p 2222 minions@ssh.miniclankers.com whoami

# Certificate is correct (should show Cloudflare Origin Certificate)
echo | openssl s_client -connect vps-2b1e18f2:443 -servername miniclankers.com 2>/dev/null \
  | openssl x509 -noout -subject -dates

# HTTP redirect works
curl -I http://miniclankers.com   # should return 301
```

---

## 9. Usage

### Expose a VM's web server

Inside the VM, start a web server:

```bash
python3 -m http.server 3000
```

Configure the proxy port:

```bash
ssh -p 2222 minions@ssh.miniclankers.com expose myapp --port 3000
```

Visit: `https://myapp.miniclankers.com`

The default proxy port is **80**. If your VM's app binds on 80, no `expose` command needed.

### Make a VM public (no login required)

```bash
ssh -p 2222 minions@ssh.miniclankers.com set-public myapp   # no login
ssh -p 2222 minions@ssh.miniclankers.com set-private myapp  # require login
```

### Custom domains (future — requires Let's Encrypt cert)

For a custom domain `custom.example.com` pointing grey-cloud to `54.37.17.133`:

```bash
# Obtain cert via certbot (HTTP-01, port 80 must be reachable)
sudo certbot certonly --standalone --preferred-challenges http -d custom.example.com

sudo mkdir -p /var/lib/minions/certs/custom.example.com
sudo cp /etc/letsencrypt/live/custom.example.com/fullchain.pem \
        /var/lib/minions/certs/custom.example.com/
sudo cp /etc/letsencrypt/live/custom.example.com/privkey.pem \
        /var/lib/minions/certs/custom.example.com/

# Add and verify via SSH gateway (once domain API is implemented)
# ssh -p 2222 minions@ssh.miniclankers.com add-domain myapp custom.example.com
```

Auto-provisioning of custom domain certs (ACME HTTP-01 built into the daemon) is in progress.

---

## 10. Architecture notes

```
minions serve --proxy-bind 0.0.0.0:443 --http-bind 0.0.0.0:80 --domain miniclankers.com
│
├── axum-server on 0.0.0.0:443 (TLS via rustls)
│   ├── SniResolver — picks cert from /var/lib/minions/certs/ based on SNI hostname
│   │   ├── *.miniclankers.com  → Cloudflare Origin Cert (15-year, placed manually)
│   │   └── custom.example.com → Let's Encrypt cert (HTTP-01, per-domain)
│   └── proxy handler
│       ├── Check custom_domains table first
│       ├── Fall back to subdomain extraction (*.miniclankers.com)
│       ├── VM lookup by name/domain
│       ├── Auth check (private VMs require session cookie)
│       └── Forward to http://{vm.ip}:{vm.proxy_port}
│
├── axum on 0.0.0.0:80 (plain HTTP)
│   ├── GET /.well-known/acme-challenge/{token}  → ACME HTTP-01 response
│   └── all other requests                       → 301 to https://
│
└── DB: vms + custom_domains
```

---

## 11. Troubleshooting

### Cloudflare 525 "SSL Handshake Failed"
The origin is not serving TLS on port 443, or the cert is missing.
```bash
ss -tlnp | grep :443        # is minions listening?
journalctl -u minions -n 50  # check for cert load errors
ls /var/lib/minions/certs/  # does *.miniclankers.com/ exist?
```

### Cloudflare 526 "Invalid SSL Certificate"
Using Full (strict) mode but the cert isn't trusted by Cloudflare.
Use a **Cloudflare Origin Certificate** (not self-signed) for the wildcard.

### 502 Bad Gateway
The VM's web server isn't running on the configured port.
```bash
ssh -p 2222 testvm@ssh.miniclankers.com
ss -tlnp | grep <port>
```

### 503 Service Unavailable
The VM is stopped.
```bash
ssh -p 2222 minions@ssh.miniclankers.com restart testvm
```

### HTTP redirect not working (custom domain)
Port 80 is blocked. Check:
```bash
ufw status
ss -tlnp | grep :80
```

### Session cookie not set
Now that TLS is native, cookies carry the `Secure` flag. Ensure you're accessing
via `https://` — any plain `http://` request gets redirected, and the browser must
follow the redirect to set the cookie.
