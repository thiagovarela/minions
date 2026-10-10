# Running Minions behind Cloudflare Tunnel

Move the public ingress from a VPS to a home machine (e.g. `minipc`) using
`cloudflared`. The tunnel is outbound-only: no public IP, no port forwarding,
no open inbound ports. Cloudflare edge terminates TLS; the minions proxy keeps
doing Host-based routing to VMs exactly as today.

```text
Internet → Cloudflare edge (TLS, WAF, caching)
             │  cloudflared tunnel (outbound only)
             ▼
        home machine
        ├─ cloudflared ──→ https://localhost:443 (minions proxy, noTLSVerify)
        ├─ minions serve (proxy on 127.0.0.1, SSH gateway on LAN/Tailscale)
        └─ VMs on the internal bridge, unchanged
```

Prerequisite: all public zones (`miniclankers.com`, plus every custom domain
zone such as `filmvision.ai`) must use Cloudflare nameservers. Export existing
records (MX, TXT, etc.) before switching NS at the registrar.

---

## 1. Prepare the machine

```bash
# KVM must be available
ls /dev/kvm

# Install minions + one-time host setup
curl -sSL https://raw.githubusercontent.com/thiagovarela/minions/main/scripts/install.sh | bash
sudo minions init --persist
sudo ./scripts/build-base-image.sh --os ubuntu
sudo ./scripts/bake-agent.sh --os ubuntu
```

## 2. Create the tunnel

```bash
# On the home machine (or anywhere, then copy the credentials JSON)
cloudflared tunnel login
cloudflared tunnel create minions
# → prints <TUNNEL-UUID>, writes ~/.cloudflared/<TUNNEL-UUID>.json

# DNS routes — apex + wildcard for the platform domain
cloudflared tunnel route dns minions miniclankers.com
cloudflared tunnel route dns minions '*.miniclankers.com'
```

Install the config from [`contrib/cloudflared/config.yml`](../contrib/cloudflared/config.yml)
to `/etc/cloudflared/config.yml`, fill in the tunnel UUID, then:

```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

## 3. Custom domains: CNAME chains (no code changes)

Do **not** point custom domains directly at the tunnel. Instead keep the
existing minions convention — CNAME to the VM subdomain — and let Cloudflare
resolve the chain:

```text
filmvision.ai            CNAME  filmvision.miniclankers.com   (proxied)
filmvision.miniclankers.com  CNAME  <TUNNEL-UUID>.cfargotunnel.com  (via wildcard route)
```

Both zones are on Cloudflare, so the edge follows the chain into the tunnel,
and `minions` DNS verification (`verify_domain_dns` accepts
`CNAME → <vm>.<base-domain>`) still passes when you add the domain in the
dashboard. Apex custom domains (e.g. `thiagovarela.com.br`) work the same way
via Cloudflare's CNAME flattening.

> If apex verification ever rejects an explicit CNAME query, either register
> the `www.` name instead, or ask for a `--force` flag on the add-domain API —
> it's a small patch.

Custom-domain TLS certs still provision automatically: the config routes
`/.well-known/acme-challenge/*` for each custom domain to the proxy's plain
HTTP listener (see `contrib/cloudflared/config.yml`), so HTTP-01 works through
the tunnel. The platform wildcard (`*.miniclankers.com`) uses DNS-01 with
`MINIONS_CF_DNS_TOKEN` and needs no inbound traffic at all.

## 4. Start minions

```bash
sudo minions serve \
  --domain miniclankers.com \
  --proxy-bind 127.0.0.1:443 \
  --http-bind 127.0.0.1:80 \
  --ssh-bind 0.0.0.0:2222 \
  --acme-email admin@miniclankers.com
```

Differences vs. the VPS setup:

| Flag | VPS (before) | Home + tunnel |
|---|---|---|
| `--proxy-bind` | `0.0.0.0:443` (public) | `127.0.0.1:443` — only `cloudflared` reaches it |
| `--http-bind` | `0.0.0.0:80` | `127.0.0.1:80` — challenges arrive via tunnel |
| `--ssh-bind` | `<public-ip>:22` | `0.0.0.0:2222` — reachable on LAN + Tailscale only |
| `--public-ip` | `54.37.17.133` | **omit** — meaningless behind CGNAT/tunnel |

`/etc/minions/env` keeps working as before (`MINIONS_API_KEY`, S3 backup
settings, `MINIONS_CF_DNS_TOKEN` for the DNS-01 wildcard).

## 5. Trusted proxies (security)

The proxy honors `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` **only
when the direct peer is trusted** — otherwise anyone could spoof client IPs to
bypass rate/connection limits. Default: localhost only, which is exactly right
for a local `cloudflared`:

```text
MINIONS_TRUSTED_PROXIES=127.0.0.1,::1     # default; add CIDRs if needed
MINIONS_TRUSTED_PROXIES=none              # ignore all forwarding headers
```

With the proxy bound to `127.0.0.1`, every request it sees comes from
`cloudflared`, `proxy_source="cloudflare"` appears in the logs, and
`country` populates from `CF-IPCountry`.

## 6. Migrate the VMs (uses the S3 backup path)

```bash
# On the VPS — first real use of the backup feature
minions backup create thiago      migration-$(date +%F)
minions backup create diana       migration-$(date +%F)
minions backup create filmvision  migration-$(date +%F)

# On minipc — same S3 config in /etc/minions/env, then:
sudo minions create thiago --cpus 2 --memory 2048 && sudo minions stop thiago
sudo minions backup restore thiago migration-<date>
# repeat for diana, filmvision
sudo minions start thiago diana filmvision
```

Keep the VPS running (but idle) for a week as fallback; the DNS cutover is
instant and reversible because Cloudflare serves both the tunnel route and any
old records you keep disabled.

## 7. Verify

```bash
# Through the tunnel
curl -sI https://miniclankers.com | head -3
curl -sI https://filmvision.ai | head -3
curl -s https://thiago.miniclankers.com

# Logs should show cloudflare as source, with country populated
journalctl -u minions -f | grep proxy_source

# SSH gateway via Tailscale/LAN
ssh -p 2222 thiago@<minipc-tailscale-ip>

# Metrics
curl -s http://127.0.0.1:3000/metrics || curl -sk https://127.0.0.1/metrics -H 'Host: miniclankers.com'
```

## Caveats

- **Cloudflare free-plan ToS (§2.8)** restricts serving video/large-file
  bandwidth through their network. App/HTML/API traffic is fine; if
  filmvision.ai serves heavy media, move assets to R2/Backblaze and keep the
  tunnel for the app.
- **Home power/ISP = your uptime.** No SLA. The tunnel reconnects
  automatically after outages.
- **Backups**: re-enable a nightly `minions backup create` cron on the home
  machine; upload bandwidth is the constraint, schedule it off-peak.
