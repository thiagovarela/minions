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
    println!("    4. Start the daemon:  sudo systemctl enable --now minions");
    println!("    5. Create a VM:       sudo minions create myvm");
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
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create {dir}"))?;
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
        std::fs::write(
            "/etc/sysctl.d/99-minions.conf",
            "net.ipv4.ip_forward = 1\n",
        )
        .context("write sysctl drop-in")?;
        ok("ip_forward persisted via /etc/sysctl.d/99-minions.conf");
    }

    Ok(())
}

// ── iptables ─────────────────────────────────────────────────────────────────

fn setup_iptables(persist: bool) -> Result<()> {
    info("setting up iptables rules");

    let main_if = detect_main_interface()?;

    // Rules to add: (table, chain, args...)
    let nat_rule: &[&str] = &[
        "-t", "nat", "-A", "POSTROUTING",
        "-s", "10.0.0.0/16",
        "-o", &main_if,
        "-j", "MASQUERADE",
    ];
    let fwd_out: &[&str] = &[
        "-I", "FORWARD",
        "-i", "br0", "-o", &main_if,
        "-j", "ACCEPT",
    ];
    let fwd_in: &[&str] = &[
        "-I", "FORWARD",
        "-i", &main_if, "-o", "br0",
        "-m", "state", "--state", "RELATED,ESTABLISHED",
        "-j", "ACCEPT",
    ];

    // NOTE: We intentionally DO NOT add a blanket "br0 -o br0 ACCEPT" rule here.
    // That rule would allow all VMs to communicate with each other, enabling:
    //   - Lateral movement between VMs
    //   - Data exfiltration from one tenant to another
    //   - VM-to-VM attacks
    //
    // VMs can still reach:
    //   - The internet (via gateway 10.0.0.1 + NAT)
    //   - The host (via 10.0.0.1)
    //
    // VMs cannot reach:
    //   - Other VMs on the same bridge (DROP by default FORWARD policy)
    //
    // If VM-to-VM communication is required for a specific use case, implement:
    //   - Per-VM firewall rules (e.g., allow only specific VM pairs)
    //   - Separate VLANs/bridges per tenant
    //   - Application-level auth in the VMs themselves

    for rule in &[nat_rule, fwd_out, fwd_in] {
        add_iptables_rule(rule)?;
    }
    ok("iptables rules added (VM isolation enabled)");

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

    let unit = r#"[Unit]
Description=Minions VM Manager Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/minions serve
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
    let _ = Command::new("systemctl")
        .args(["daemon-reload"])
        .status();

    ok(format!(
        "systemd unit installed at {SYSTEMD_UNIT_PATH}\n  \
         Enable with: sudo systemctl enable --now minions"
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
