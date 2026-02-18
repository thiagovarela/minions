//! TAP device management and MAC address generation.

use anyhow::{Context, Result};
use std::process::Command;

/// Create a TAP device, attach it to br0, bring it up, and enable bridge
/// port isolation so this VM cannot communicate directly with other VMs.
///
/// Bridge port isolation (`bridge link set dev <tap> isolated on`) is a
/// kernel-level Layer-2 mechanism (available since Linux 4.18 via
/// `IFLA_BRPORT_ISOLATED`): the bridge will not forward Ethernet frames
/// between two isolated ports, regardless of iptables rules or whether
/// `br_netfilter` is loaded.  Traffic from an isolated port can only reach
/// the bridge itself (the host at `10.0.0.1`), giving full VM-to-VM
/// isolation with a single sysfs knob.
pub fn create_tap(name: &str) -> Result<String> {
    let tap = tap_name(name);

    run("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
        .with_context(|| format!("create TAP {tap}"))?;

    run("ip", &["link", "set", &tap, "master", "br0"])
        .with_context(|| format!("attach {tap} to br0"))?;

    // Isolate this bridge port so frames cannot be forwarded to any other
    // isolated port (i.e. any other VM's TAP device).  This is a Layer-2
    // control that does not depend on iptables or br_netfilter.
    run("bridge", &["link", "set", "dev", &tap, "isolated", "on"])
        .with_context(|| format!("set bridge port isolation on {tap}"))?;

    run("ip", &["link", "set", &tap, "up"])
        .with_context(|| format!("bring up {tap}"))?;

    Ok(tap)
}

/// Create a TAP device with an exact device name (used when restarting a
/// stopped VM whose tap name is already stored in the DB).
pub fn create_tap_named(tap: &str) -> Result<String> {
    run("ip", &["tuntap", "add", "dev", tap, "mode", "tap"])
        .with_context(|| format!("create TAP {tap}"))?;
    run("ip", &["link", "set", tap, "master", "br0"])
        .with_context(|| format!("attach {tap} to br0"))?;
    run("bridge", &["link", "set", "dev", tap, "isolated", "on"])
        .with_context(|| format!("set bridge port isolation on {tap}"))?;
    run("ip", &["link", "set", tap, "up"])
        .with_context(|| format!("bring up {tap}"))?;
    Ok(tap.to_string())
}

/// Delete a TAP device by VM name (derives the tap device name).
pub fn destroy_tap(name: &str) -> Result<()> {
    destroy_tap_device(&tap_name(name))
}

/// Delete a TAP device by its exact device name.
/// Use this when you have the stored tap name from the DB (e.g. after rename).
pub fn destroy_tap_device(tap: &str) -> Result<()> {
    // Best-effort: ignore errors if device doesn't exist.
    let _ = run("ip", &["link", "del", tap]);
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

/// Public alias so callers (e.g. `vm::rename`) can compute the TAP name
/// without duplicating the truncation logic.
pub fn tap_name_for(name: &str) -> String {
    tap_name(name)
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
