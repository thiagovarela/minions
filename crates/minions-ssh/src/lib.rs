//! `minions-ssh` — SSH gateway for MINICLANKERS.COM.
//!
//! Provides two modes on a single port:
//!
//! * **Command mode** — `ssh minions@ssh.miniclankers.com [command]`
//!   Authenticated by public key. Unregistered users are prompted for an email.
//!   Commands map to the local minions HTTP API.
//!
//! * **Proxy mode** — `ssh <vmname>@ssh.miniclankers.com`
//!   The gateway authenticates to the VM's sshd using the gateway's own proxy
//!   key (injected into every VM's `/root/.ssh/authorized_keys` at creation).

use std::sync::Arc;

use anyhow::{Context, Result};
use russh::server::Server as _;
use russh_keys::key::KeyPair;
use tracing::info;

pub mod commands;
pub mod db;
pub mod proxy;
pub mod server;

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for the SSH gateway.
#[derive(Clone)]
pub struct GatewayConfig {
    /// Path to the SQLite state DB (shared with the main daemon).
    pub db_path: String,
    /// SSH username that triggers command mode (e.g. "minions").
    pub command_user: String,
    /// Base URL of the local minions HTTP API (e.g. "http://127.0.0.1:3000").
    pub api_base_url: String,
    /// API key for the minions HTTP API (if MINIONS_API_KEY is set).
    pub api_key: Option<String>,
    /// Gateway proxy key used to authenticate to VMs.
    pub proxy_key: Arc<KeyPair>,
}

// ── Key paths ─────────────────────────────────────────────────────────────────

pub const HOST_KEY_PATH: &str = "/var/lib/minions/ssh_host_key";
pub const PROXY_KEY_PATH: &str = "/var/lib/minions/proxy_key";
pub const PROXY_PUBKEY_PATH: &str = "/var/lib/minions/proxy_key.pub";

// ── Key management ────────────────────────────────────────────────────────────

/// Generate the SSH host key and proxy key if they don't exist yet.
/// Returns `(host_key, proxy_key, proxy_pubkey_openssh)`.
pub fn ensure_keys() -> Result<(KeyPair, KeyPair, String)> {
    let host_key = ensure_key(HOST_KEY_PATH).context("host key")?;
    let (proxy_key, proxy_pubkey) = ensure_proxy_key(PROXY_KEY_PATH, PROXY_PUBKEY_PATH)
        .context("proxy key")?;
    Ok((host_key, proxy_key, proxy_pubkey))
}

fn ensure_key(path: &str) -> Result<KeyPair> {
    if std::path::Path::new(path).exists() {
        let kp = russh_keys::load_secret_key(path, None)
            .with_context(|| format!("load key from {}", path))?;
        return Ok(kp);
    }
    // Generate with ssh-keygen — most reliable across platforms.
    generate_ed25519_key(path)?;
    let kp = russh_keys::load_secret_key(path, None)
        .with_context(|| format!("load generated key from {}", path))?;
    info!("generated new SSH host key at {}", path);
    Ok(kp)
}

fn ensure_proxy_key(key_path: &str, pub_path: &str) -> Result<(KeyPair, String)> {
    if std::path::Path::new(key_path).exists() {
        let kp = russh_keys::load_secret_key(key_path, None)
            .with_context(|| format!("load proxy key from {}", key_path))?;
        let pubkey = std::fs::read_to_string(pub_path)
            .with_context(|| format!("read proxy pubkey from {}", pub_path))?;
        return Ok((kp, pubkey.trim().to_string()));
    }
    // Generate key pair.
    generate_ed25519_key(key_path)?;
    // Write public key.
    let kp = russh_keys::load_secret_key(key_path, None)
        .with_context(|| format!("load generated proxy key from {}", key_path))?;
    let pubkey_str = public_key_openssh_line(&kp);
    std::fs::write(pub_path, format!("{}\n", pubkey_str))
        .with_context(|| format!("write proxy pubkey to {}", pub_path))?;
    info!("generated new proxy key at {}", key_path);
    info!("proxy public key: {}", pubkey_str);
    Ok((kp, pubkey_str))
}

/// Run `ssh-keygen -t ed25519 -f <path> -N ""` to generate a key.
fn generate_ed25519_key(path: &str) -> Result<()> {
    // Ensure parent directory exists.
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let status = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", path, "-N", ""])
        .status()
        .context("run ssh-keygen (is openssh installed?)")?;
    if !status.success() {
        anyhow::bail!("ssh-keygen failed for {}", path);
    }
    // Remove the .pub file ssh-keygen creates (we manage pubkeys ourselves).
    let _ = std::fs::remove_file(format!("{}.pub", path));
    Ok(())
}

/// Format the gateway's proxy key as an OpenSSH authorized_keys line.
pub fn public_key_openssh_line(kp: &KeyPair) -> String {
    use russh_keys::PublicKeyBase64;
    let pk = kp.clone_public_key().expect("clone public key");
    format!("{} {} minions-gateway", pk.name(), pk.public_key_base64())
}

// ── Serve ─────────────────────────────────────────────────────────────────────

/// Start the SSH gateway.
///
/// `host_key`   — server host key (identifies the gateway to clients)
/// `proxy_key`  — key used by the gateway to authenticate to VMs
/// `bind`       — address + port to listen on (e.g. "0.0.0.0:22")
/// `config`     — gateway config
pub async fn serve(
    host_key: KeyPair,
    config: GatewayConfig,
    bind: &str,
) -> Result<()> {
    let russh_config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_millis(300),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        ..Default::default()
    });

    let mut srv = server::SshServer { config: Arc::new(config) };

    let addr: std::net::SocketAddr = bind.parse()
        .with_context(|| format!("parse bind address: {}", bind))?;

    info!("SSH gateway listening on {}", bind);
    srv.run_on_address(russh_config, addr)
        .await
        .context("SSH gateway error")
}
