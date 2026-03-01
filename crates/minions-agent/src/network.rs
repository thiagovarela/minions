use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

/// Configure VM networking: assign IP, set default gateway, write DNS servers.
pub async fn configure(ip: &str, gateway: &str, dns_servers: &[String]) -> Result<()> {
    info!("configuring network: ip={}, gateway={}", ip, gateway);

    // Validate inputs before executing any commands
    validate_ip_with_cidr(ip)?;
    validate_ip_addr(gateway)?;
    for dns in dns_servers {
        validate_ip_addr(dns)?;
    }

    // Find the first ethernet interface (e.g. eth0, enp0s3)
    let interface = find_ethernet_interface().await?;
    let ip_cmd = resolve_ip_command();

    info!("found ethernet interface: {}", interface);
    info!("using ip command: {}", ip_cmd);

    // Flush existing IP addresses on the interface
    run_command(ip_cmd, &["addr", "flush", "dev", &interface]).await?;

    // Assign IP address
    run_command(ip_cmd, &["addr", "add", ip, "dev", &interface]).await?;

    // Bring interface up
    run_command(ip_cmd, &["link", "set", &interface, "up"]).await?;

    // Set default gateway
    run_command(ip_cmd, &["route", "add", "default", "via", gateway]).await?;

    // Write DNS servers to /etc/resolv.conf
    write_resolv_conf(dns_servers)?;

    info!("network configuration complete");

    Ok(())
}

async fn find_ethernet_interface() -> Result<String> {
    // List all interfaces under /sys/class/net/ that start with 'e' (eth0, enp0s3, etc.)
    let mut entries = tokio::fs::read_dir("/sys/class/net")
        .await
        .context("failed to read /sys/class/net")?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .context("failed to iterate interfaces")?
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Match eth*, enp*, ens*
        if name_str.starts_with("eth") || name_str.starts_with("enp") || name_str.starts_with("ens")
        {
            return Ok(name_str.to_string());
        }
    }

    anyhow::bail!("no ethernet interface found")
}

fn resolve_ip_command() -> &'static str {
    const CANDIDATES: &[&str] = &[
        "/usr/sbin/ip",
        "/usr/bin/ip",
        "/run/current-system/sw/bin/ip",     // NixOS
        "/nix/var/nix/profiles/system/sw/bin/ip", // NixOS fallback
    ];

    for candidate in CANDIDATES {
        if Path::new(candidate).exists() {
            return candidate;
        }
    }

    // Fallback to PATH lookup (works on Ubuntu/Fedora).
    "ip"
}

async fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("failed to execute: {} {:?}", cmd, args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "command failed: {} {:?}\nstderr: {}",
            cmd,
            args,
            stderr.trim()
        );
    }

    Ok(())
}

fn write_resolv_conf(dns_servers: &[String]) -> Result<()> {
    let mut content = String::new();
    for dns in dns_servers {
        content.push_str(&format!("nameserver {}\n", dns));
    }

    std::fs::write("/etc/resolv.conf", content).context("failed to write /etc/resolv.conf")?;

    Ok(())
}

// ── Input validation ──────────────────────────────────────────────────────────

/// Validate IP address with CIDR notation (e.g., "10.0.0.2/16").
fn validate_ip_with_cidr(ip: &str) -> Result<()> {
    let parts: Vec<&str> = ip.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "invalid IP with CIDR: '{}' (expected format: 10.0.0.2/16)",
            ip
        );
    }

    // Validate IP address part
    parts[0]
        .parse::<IpAddr>()
        .with_context(|| format!("invalid IP address in '{}'", ip))?;

    // Validate CIDR prefix length
    let prefix_len: u8 = parts[1]
        .parse()
        .with_context(|| format!("invalid CIDR prefix length in '{}'", ip))?;

    if prefix_len > 32 {
        anyhow::bail!("CIDR prefix length {} exceeds maximum 32", prefix_len);
    }

    Ok(())
}

/// Validate a plain IP address (no CIDR).
fn validate_ip_addr(ip: &str) -> Result<()> {
    ip.parse::<IpAddr>()
        .with_context(|| format!("invalid IP address: '{}'", ip))?;
    Ok(())
}
