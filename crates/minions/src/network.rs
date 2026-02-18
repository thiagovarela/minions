//! TAP device management and MAC address generation.

use anyhow::{Context, Result};
use std::process::Command;

/// Create a TAP device, attach it to br0, and bring it up.
pub fn create_tap(name: &str) -> Result<String> {
    let tap = tap_name(name);

    run("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
        .with_context(|| format!("create TAP {tap}"))?;

    run("ip", &["link", "set", &tap, "master", "br0"])
        .with_context(|| format!("attach {tap} to br0"))?;

    run("ip", &["link", "set", &tap, "up"])
        .with_context(|| format!("bring up {tap}"))?;

    Ok(tap)
}

/// Delete a TAP device.
pub fn destroy_tap(name: &str) -> Result<()> {
    let tap = tap_name(name);
    // Best-effort: ignore errors if device doesn't exist.
    let _ = run("ip", &["link", "del", &tap]);
    Ok(())
}

/// Verify that bridge br0 exists.
pub fn check_bridge() -> Result<()> {
    let output = Command::new("ip")
        .args(["link", "show", "br0"])
        .output()
        .context("run ip link show br0")?;
    if !output.status.success() {
        anyhow::bail!(
            "bridge br0 not found — run the Phase 1/2 host setup first.\n\
             Hint: ip link add br0 type bridge && ip addr add 10.0.0.1/16 dev br0 && ip link set br0 up"
        );
    }
    Ok(())
}

/// Generate a deterministic MAC address from a VSOCK CID.
/// Format: `52:54:00:00:{cid_high}:{cid_low}`
pub fn generate_mac(cid: u32) -> String {
    let high = (cid >> 8) as u8;
    let low = (cid & 0xff) as u8;
    format!("52:54:00:00:{high:02x}:{low:02x}")
}

/// TAP device name derived from VM name (max 15 chars total).
fn tap_name(name: &str) -> String {
    let prefix = "tap-";
    let max_suffix = 15 - prefix.len(); // 11
    let suffix = if name.len() > max_suffix {
        &name[..max_suffix]
    } else {
        name
    };
    format!("{prefix}{suffix}")
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("spawn {cmd}"))?;
    if !status.success() {
        anyhow::bail!("{cmd} {} failed: {status}", args.join(" "));
    }
    Ok(())
}
