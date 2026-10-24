#!/usr/bin/env bash
# Minions boot helper — ensure host networking and start the VMs.
#
# Why this exists:
#   `minions init --persist` persists sysctl, module loading and iptables, but
#   NOT the br0 bridge, and the daemon never auto-starts VMs (reconcile() only
#   marks dead ones as stopped). Without this, a reboot leaves every VM down
#   until someone recreates the bridge and starts them by hand.
#
# Install:
#   sudo install -m 755 contrib/minions-boot.sh /usr/local/bin/minions-boot.sh
#   sudo install -m 644 contrib/systemd/minions-boot.service /etc/systemd/system/
#   sudo systemctl daemon-reload && sudo systemctl enable --now minions-boot
set -u

BRIDGE=br0
API_PORT=3000
log() { echo "[minions-boot] $*"; }

# ── 1. Bridge ────────────────────────────────────────────────────────────────
if ip link show "$BRIDGE" >/dev/null 2>&1; then
  log "bridge $BRIDGE present"
else
  log "creating bridge $BRIDGE"
  ip link add "$BRIDGE" type bridge \
    && ip addr add 10.0.0.1/16 dev "$BRIDGE" \
    && ip link set "$BRIDGE" up \
    || log "WARNING: could not create bridge $BRIDGE"
fi

# ── 2. Kernel bits (NAT + bridge filtering) ──────────────────────────────────
sysctl -qw net.ipv4.ip_forward=1 2>/dev/null || true
modprobe br_netfilter 2>/dev/null || true
if [ -w /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
  echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
fi

# ── 3. VM egress NAT ─────────────────────────────────────────────────────────
# Add the masquerade rule directly instead of `iptables-restore`ing a whole
# ruleset: a restore flushes every table, which silently wipes ufw's chains —
# ufw then reports "Status: inactive" even though it is enabled, leaving the
# host without a firewall until `ufw reload` is run.
WAN_IF=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
if [ -n "${WAN_IF:-}" ] && ! iptables -t nat -C POSTROUTING -s 10.0.0.0/16 -o "$WAN_IF" -j MASQUERADE 2>/dev/null; then
  log "adding VM masquerade rule on $WAN_IF"
  iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o "$WAN_IF" -j MASQUERADE \
    || log "WARNING: could not add masquerade rule"
fi

# ── 3b. Re-apply ufw if it manages this host ─────────────────────────────────
# Something earlier in the boot path (netfilter-persistent, or a manual
# iptables-restore) may have replaced the tables. Reloading ufw restores its
# chains and the deny-incoming policy. Safe to call when ufw is disabled.
if command -v ufw >/dev/null 2>&1 && grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then
  if ufw reload >/dev/null 2>&1; then
    log "ufw reloaded ($(ufw status | head -1))"
  else
    log "WARNING: ufw reload failed"
  fi
fi

# ── 4. Wait for the daemon API ───────────────────────────────────────────────
for _ in $(seq 1 30); do
  (echo > "/dev/tcp/127.0.0.1/$API_PORT") >/dev/null 2>&1 && break
  sleep 1
done

# ── 5. Start every VM the daemon reports as stopped ──────────────────────────
log "starting stopped VMs"
if ! minions start --all; then
  log "WARNING: 'minions start --all' failed (check MINIONS_API_KEY in /etc/minions/env)"
fi

log "done"
