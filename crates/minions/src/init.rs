//! Host setup automation: bridge, iptables, directories, systemd unit.
//!
//! All operations are idempotent — safe to run multiple times.

use anyhow::{Context, Result};
use std::process::Command;

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/minions.service";
const SYSCTL_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

pub fn run(persist: bool) -> Result<()> {
    check_kvm()?;
    setup_directories()?;
    setup_bridge()?;
    enable_ip_forward(persist)?;
    load_br_netfilter(persist)?;
    setup_iptables(persist)?;
    install_systemd_unit()?;

    println!();
    println!("────────────────────────────────────────────");
    ok("Host setup complete!");
    println!();
    println!("  Next steps:");
    println!("    1. Copy base image:   /var/lib/minions/images/base-ubuntu.ext4");
    println!("    2. Copy kernel:       /var/lib/minions/kernel/vmlinux");
    println!("    3. Bake the agent:    sudo ./scripts/bake-agent.sh");
    println!(
        "    4. Place TLS cert:    /var/lib/minions/certs/'*.yourdomain.com'/{{fullchain,privkey}}.pem"
    );
    println!("    5. Edit env:          /etc/minions/env  (set MINIONS_API_KEY)");
    println!(
        "    6. Edit unit:         /etc/systemd/system/minions.service  (set --domain, --public-ip)"
    );
    println!("    7. Start the daemon:  sudo systemctl enable --now minions");
    println!("    8. Create a VM:       ssh -p 2222 minions@ssh.yourdomain.com new");
    println!("────────────────────────────────────────────");

    Ok(())
}

// ── KVM ───────────────────────────────────────────────────────────────────────

fn check_kvm() -> Result<()> {
    info("checking KVM availability");
    if !std::path::Path::new("/dev/kvm").exists() {
        anyhow::bail!(
            "/dev/kvm not found.\n\
             Ensure KVM is enabled: lsmod | grep kvm\n\
             On AMD: kvm_amd, on Intel: kvm_intel"
        );
    }
    ok("KVM available");
    Ok(())
}

// ── Directories ───────────────────────────────────────────────────────────────

fn setup_directories() -> Result<()> {
    info("creating directories");
    for dir in &[
        "/var/lib/minions/kernel",
        "/var/lib/minions/images",
        "/var/lib/minions/vms",
        "/run/minions",
    ] {
        std::fs::create_dir_all(dir).with_context(|| format!("create {dir}"))?;
    }
    ok("directories ready");
    Ok(())
}

// ── Bridge ────────────────────────────────────────────────────────────────────

fn setup_bridge() -> Result<()> {
    info("setting up bridge br0");

    // Check if br0 already exists.
    let out = Command::new("ip")
        .args(["link", "show", "br0"])
        .output()
        .context("ip link show br0")?;

    if out.status.success() {
        ok("bridge br0 already exists — skipping");
        return Ok(());
    }

    exec_cmd("ip", &["link", "add", "br0", "type", "bridge"])?;
    exec_cmd("ip", &["addr", "add", "10.0.0.1/16", "dev", "br0"])?;
    exec_cmd("ip", &["link", "set", "br0", "up"])?;
    ok("bridge br0 created at 10.0.0.1/16");
    Ok(())
}

// ── IP forwarding ─────────────────────────────────────────────────────────────

fn enable_ip_forward(persist: bool) -> Result<()> {
    info("enabling IP forwarding");
    std::fs::write(SYSCTL_FORWARD, "1\n").context("write ip_forward")?;
    ok("ip_forward = 1");

    if persist {
        // Write a sysctl drop-in so it survives reboots.
        std::fs::create_dir_all("/etc/sysctl.d")?;
        std::fs::write("/etc/sysctl.d/99-minions.conf", "net.ipv4.ip_forward = 1\n")
            .context("write sysctl drop-in")?;
        ok("ip_forward persisted via /etc/sysctl.d/99-minions.conf");
    }

    Ok(())
}

// ── br_netfilter ──────────────────────────────────────────────────────────────

/// Load br_netfilter and enable bridge-nf-call-iptables.
///
/// `br_netfilter` routes bridge-internal packets (VM A → switch → VM B)
/// through the iptables FORWARD chain.  Without it, intra-bridge traffic
/// bypasses iptables entirely and the DROP rule below would have no effect.
///
/// This is a defence-in-depth layer: bridge port isolation (set per TAP in
/// `network::create_tap`) already blocks VM-to-VM frames at Layer 2.
/// `br_netfilter` + the DROP rule catch any edge cases where isolation is
/// not yet in effect (e.g. TAP devices created before this fix, or on kernels
/// where bridge port isolation is unavailable).
fn load_br_netfilter(persist: bool) -> Result<()> {
    info("loading br_netfilter kernel module");

    // Best-effort: may fail inside containers that share the host kernel without
    // permission to load modules.  Bridge port isolation still provides L2 isolation.
    let loaded = Command::new("modprobe")
        .arg("br_netfilter")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if loaded {
        // Enable the sysctl so the module actually intercepts bridge frames.
        let _ = std::fs::write("/proc/sys/net/bridge/bridge-nf-call-iptables", "1\n");
        ok("br_netfilter loaded, bridge-nf-call-iptables = 1");
    } else {
        println!(
            "⚠  modprobe br_netfilter failed — iptables DROP rule will have no effect \
             on bridge-internal traffic.\n   \
             Bridge port isolation (TAP isolated flag) still provides Layer-2 VM isolation."
        );
    }

    if persist {
        // Persist module loading across reboots.
        std::fs::create_dir_all("/etc/modules-load.d")?;
        std::fs::write("/etc/modules-load.d/minions.conf", "br_netfilter\n")
            .context("write /etc/modules-load.d/minions.conf")?;

        // Append bridge sysctl to the existing minions sysctl drop-in
        // (created by enable_ip_forward).  Use a separate file to avoid
        // duplicating the ip_forward line.
        std::fs::write(
            "/etc/sysctl.d/99-minions-bridge.conf",
            "net.bridge.bridge-nf-call-iptables = 1\n",
        )
        .context("write /etc/sysctl.d/99-minions-bridge.conf")?;

        ok("br_netfilter module load and bridge-nf-call-iptables persisted");
    }

    Ok(())
}

// ── iptables ─────────────────────────────────────────────────────────────────

fn setup_iptables(persist: bool) -> Result<()> {
    info("setting up iptables rules");

    let main_if = detect_main_interface()?;

    // NAT: masquerade VM traffic going out to the internet.
    let nat_rule: &[&str] = &[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        "10.0.0.0/16",
        "-o",
        &main_if,
        "-j",
        "MASQUERADE",
    ];
    // Allow VMs to reach the internet.
    let fwd_out: &[&str] = &["-I", "FORWARD", "-i", "br0", "-o", &main_if, "-j", "ACCEPT"];
    // Allow established/related return traffic back to VMs.
    let fwd_in: &[&str] = &[
        "-I",
        "FORWARD",
        "-i",
        &main_if,
        "-o",
        "br0",
        "-m",
        "state",
        "--state",
        "RELATED,ESTABLISHED",
        "-j",
        "ACCEPT",
    ];

    // Defence-in-depth: explicitly DROP traffic routed between bridge ports
    // (VM → VM).  This catches any scenario where br_netfilter is loaded but
    // bridge port isolation is not set (e.g. TAPs created before this fix).
    //
    // When br_netfilter is active, bridge-internal packets traverse the
    // FORWARD chain.  Inserting this rule at position 1 ensures it is
    // evaluated before any more-permissive rules that Docker, Tailscale, or
    // earlier manual setups may have added (e.g. a stale "br0 -o br0 ACCEPT").
    //
    // VMs can still reach:
    //   - The internet (via gateway 10.0.0.1 + NAT)
    //   - The host (10.0.0.1 is the bridge IP, not a bridge port)
    //
    // VMs cannot reach each other via:
    //   - Layer 2 (bridge port isolation, set in network::create_tap)
    //   - Layer 3 (this DROP rule, when br_netfilter is loaded)
    let fwd_isolate: &[&str] = &["-I", "FORWARD", "-i", "br0", "-o", "br0", "-j", "DROP"];

    for rule in &[nat_rule, fwd_out, fwd_in, fwd_isolate] {
        add_iptables_rule(rule)?;
    }
    ok("iptables rules added (VM-to-VM traffic blocked)");

    if persist {
        // Install iptables-persistent and save rules.
        let _ = Command::new("apt-get")
            .args(["install", "-y", "-q", "iptables-persistent"])
            .status();
        let _ = Command::new("sh")
            .arg("-c")
            .arg("iptables-save > /etc/iptables/rules.v4")
            .status();
        ok("iptables rules persisted via iptables-persistent");
    }

    Ok(())
}

/// Add an iptables rule, skipping if it already exists.
fn add_iptables_rule(args: &[&str]) -> Result<()> {
    // Build check args: replace -A/-I with -C.
    let check_args: Vec<&str> = args
        .iter()
        .map(|a| match *a {
            "-A" | "-I" => "-C",
            other => other,
        })
        .collect();

    let exists = Command::new("iptables")
        .args(&check_args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if exists {
        return Ok(());
    }

    exec_cmd("iptables", args)?;
    Ok(())
}

fn detect_main_interface() -> Result<String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("ip route show default")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for word in stdout.split_whitespace().collect::<Vec<_>>().windows(2) {
        if word[0] == "dev" {
            return Ok(word[1].to_string());
        }
    }
    anyhow::bail!("could not detect default network interface")
}

// ── Systemd unit ──────────────────────────────────────────────────────────────

fn install_systemd_unit() -> Result<()> {
    info("installing minions.service systemd unit");

    // Write the environment file if it doesn't exist yet.
    // This is where secrets live (API key, CF token, etc.) — separate from the unit
    // so it can be updated without touching the unit file.
    let env_dir = "/etc/minions";
    let env_path = "/etc/minions/env";
    std::fs::create_dir_all(env_dir)?;
    if !std::path::Path::new(env_path).exists() {
        // Detect SSH pubkey path for MINIONS_SSH_PUBKEY_PATH.
        let ssh_pubkey_line = detect_user_ssh_pubkey_path()
            .map(|p| format!("MINIONS_SSH_PUBKEY_PATH={p}\n"))
            .unwrap_or_else(|| {
                "# MINIONS_SSH_PUBKEY_PATH=/root/.ssh/authorized_keys\n".to_string()
            });

        let env_content = format!(
            "# Minions environment configuration\n\
             # Set a strong random secret: openssl rand -hex 32\n\
             MINIONS_API_KEY=\n\
             {ssh_pubkey_line}\
             # Cloudflare DNS API token (Zone:DNS:Edit) for DNS-01 wildcard cert provisioning\n\
             # MINIONS_CF_DNS_TOKEN=\n"
        );
        std::fs::write(env_path, env_content)?;
        // Restrict to root-only — contains secrets.
        let _ = Command::new("chmod").args(["600", env_path]).status();
        ok(format!(
            "environment file created at {env_path} — fill in MINIONS_API_KEY"
        ));
    } else {
        ok(format!("environment file already exists at {env_path}"));
    }

    // The unit uses EnvironmentFile so secrets stay out of `systemctl cat` output.
    let unit = r#"[Unit]
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
    --acme-email admin@miniclankers.com
EnvironmentFile=-/etc/minions/env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;

    std::fs::write(SYSTEMD_UNIT_PATH, unit)
        .with_context(|| format!("write {SYSTEMD_UNIT_PATH}"))?;

    // Reload systemd so the new unit is visible.
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();

    ok(format!(
        "systemd unit installed at {SYSTEMD_UNIT_PATH}\n  \
         Edit the unit to set --domain, --public-ip, --acme-email.\n  \
         Fill in /etc/minions/env with MINIONS_API_KEY.\n  \
         Then: sudo systemctl enable --now minions"
    ));
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn exec_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("spawn {cmd}"))?;
    if !status.success() {
        anyhow::bail!("{cmd} {} exited with {status}", args.join(" "));
    }
    Ok(())
}

fn info(msg: &str) {
    println!("  [init] {msg}…");
}

fn ok(msg: impl std::fmt::Display) {
    println!("✓ {msg}");
}

/// Find the invoking user's SSH public key path.
/// Returns the path string if a key is found, None otherwise.
fn detect_user_ssh_pubkey_path() -> Option<String> {
    // When run as `sudo minions init`, SUDO_USER is the actual user.
    let home = if let Ok(user) = std::env::var("SUDO_USER") {
        // Look up home dir from /etc/passwd.
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            content.lines().find_map(|line| {
                let fields: Vec<&str> = line.splitn(7, ':').collect();
                if fields.len() >= 6 && fields[0] == user {
                    Some(fields[5].to_string())
                } else {
                    None
                }
            })
        } else {
            None
        }
    } else {
        std::env::var("HOME").ok()
    }?;

    for name in &["id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"] {
        let path = format!("{home}/.ssh/{name}");
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    None
}
