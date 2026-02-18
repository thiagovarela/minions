//! Daemon mode: startup reconciliation + HTTP server.

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::{info, warn};

use crate::{api, auth, dashboard, db, hypervisor, metrics, network};

/// Shared state passed to every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    /// Path to the SQLite database (each handler opens its own connection).
    pub db_path: Arc<String>,
    /// SSH public key to inject into new VMs.
    pub ssh_pubkey: Option<Arc<String>>,
    /// Authentication configuration.
    pub auth: auth::AuthConfig,
    /// Allowed CORS origins (e.g. `["https://app.example.com"]`).
    /// Empty means CORS is disabled. Set via `MINIONS_CORS_ORIGINS` env var.
    pub cors_origins: Vec<String>,
    /// Shared metrics store updated by the background collector.
    pub metrics: metrics::MetricsStore,
    /// Dashboard session tokens (in-memory, cleared on restart).
    pub sessions: dashboard::DashboardSessions,
}

/// Reconcile DB state with reality.
///
/// Called once on daemon startup to handle VMs that died while the daemon
/// was offline (host reboot, crash, OOM kill).
pub fn reconcile(db_path: &str) -> Result<()> {
    info!("reconciling VM state…");
    let conn = db::open(db_path)?;
    let vms = db::list_vms(&conn)?;

    for vm in &vms {
        match vm.status.as_str() {
            "running" | "starting" | "creating" | "stopping" => {
                if !hypervisor::is_alive_pid(vm.ch_pid) {
                    warn!(
                        name = %vm.name,
                        status = %vm.status,
                        "CH process dead — marking stopped and cleaning up"
                    );
                    // Best-effort cleanup — use stored paths, not derived from name.
                    let _ = network::destroy_tap_device(&vm.tap_device);
                    for sock in [&vm.ch_api_socket, &vm.ch_vsock_socket] {
                        let _ = std::fs::remove_file(sock);
                    }
                    let _ = db::update_vm_status(&conn, &vm.name, "stopped", None);
                } else {
                    info!(name = %vm.name, "VM alive ✓");
                }
            }
            _ => {} // stopped / error — nothing to do
        }
    }

    // Clean up orphan socket files in /run/minions/ with no DB entry.
    cleanup_orphan_sockets(&conn)?;

    info!("reconciliation complete");
    Ok(())
}

fn cleanup_orphan_sockets(conn: &rusqlite::Connection) -> Result<()> {
    let run_dir = std::path::Path::new(hypervisor::RUN_DIR);
    if !run_dir.exists() {
        return Ok(());
    }

    let vms = db::list_vms(conn)?;
    let known_names: std::collections::HashSet<String> =
        vms.into_iter().map(|v| v.name).collect();

    for entry in std::fs::read_dir(run_dir)? {
        let entry = entry?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();

        // Socket files look like "{name}.sock" or "{name}.vsock"
        let vm_name = fname
            .strip_suffix(".sock")
            .or_else(|| fname.strip_suffix(".vsock"));

        if let Some(name) = vm_name {
            if !known_names.contains(name) {
                warn!("orphan socket {:?} — removing", entry.path());
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    Ok(())
}

/// Start the HTTP API daemon (and optionally the SSH gateway + HTTP proxy).
pub async fn serve(
    db_path: String,
    bind: String,
    ssh_pubkey: Option<String>,
    ssh_bind: Option<String>,
    proxy_bind: Option<String>,
    http_bind: Option<String>,
    domain: Option<String>,
    public_ip: Option<String>,
    acme_email: Option<String>,
    acme_staging: bool,
) -> Result<()> {
    reconcile(&db_path)?;

    // ── API key ───────────────────────────────────────────────────────────────
    let api_key = std::env::var("MINIONS_API_KEY").ok();
    if api_key.is_none() {
        warn!("⚠️  MINIONS_API_KEY not set — API authentication DISABLED (INSECURE)");
        warn!("   Set MINIONS_API_KEY=<secret> to enable authentication");
    } else {
        info!("✓ API authentication enabled");
    }

    let auth = auth::AuthConfig::new(api_key.clone());

    // ── CORS origins ──────────────────────────────────────────────────────────
    let cors_origins: Vec<String> = std::env::var("MINIONS_CORS_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cors_origins.is_empty() {
        info!("CORS disabled (set MINIONS_CORS_ORIGINS=https://example.com to enable)");
    } else {
        info!("✓ CORS allowed origins: {:?}", cors_origins);
    }

    match &ssh_pubkey {
        Some(key) => info!("✓ SSH public key loaded ({} chars) — will be injected into new VMs", key.len()),
        None => warn!("⚠️  No SSH public key found — VMs will require manual key setup\n   Set MINIONS_SSH_PUBKEY_PATH=/path/to/key.pub or run 'minions init' to auto-detect"),
    }

    // ── Metrics store + background collector ──────────────────────────────────
    let metrics_store = metrics::MetricsStore::new();
    let metrics_interval: u64 = std::env::var("MINIONS_METRICS_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    metrics::spawn_collector(db_path.clone(), metrics_store.clone(), metrics_interval);
    info!("✓ Metrics collector started (interval: {metrics_interval}s)");

    let state = AppState {
        db_path: Arc::new(db_path.clone()),
        ssh_pubkey: ssh_pubkey.map(Arc::new),
        auth,
        cors_origins,
        metrics: metrics_store,
        sessions: dashboard::DashboardSessions::new(),
    };

    let app = api::router(state.clone())
        .merge(dashboard::router().with_state(state))
        // Redirect bare root to dashboard
        .route("/", axum::routing::get(|| async { axum::response::Redirect::to("/dashboard/login") }));

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;

    info!("minions daemon listening on http://{bind}");

    // ── SSH gateway (optional) ─────────────────────────────────────────────────
    if let Some(ssh_bind_addr) = ssh_bind {
        let (host_key, proxy_key, proxy_pubkey) =
            minions_ssh::ensure_keys().context("SSH gateway key setup")?;

        info!("✓ SSH host key loaded");
        info!("✓ Proxy public key: {}", proxy_pubkey);

        // Derive the HTTP API URL from the bind address (use 127.0.0.1 always).
        let port = bind.rsplit(':').next().unwrap_or("3000");
        let api_base_url = format!("http://127.0.0.1:{}", port);

        let gateway_config = minions_ssh::GatewayConfig {
            db_path: db_path.clone(),
            command_user: "minions".to_string(),
            api_base_url,
            api_key: api_key.clone(),
            proxy_key: std::sync::Arc::new(proxy_key),
        };

        let ssh_bind_clone = ssh_bind_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = minions_ssh::serve(host_key, gateway_config, &ssh_bind_clone).await {
                tracing::error!("SSH gateway error: {:#}", e);
            }
        });

        info!("SSH gateway starting on {}", ssh_bind_addr);
    } else {
        info!("SSH gateway disabled (use --ssh-bind to enable)");
    }

    // ── HTTPS reverse proxy (optional) ────────────────────────────────────────
    if let Some(https_addr) = proxy_bind {
        let base_domain = domain.clone().unwrap_or_else(|| {
            warn!("⚠️  --proxy-bind set but --domain not provided; defaulting to 'localhost'");
            "localhost".to_string()
        });

        let http_addr = http_bind.clone().unwrap_or_else(|| "0.0.0.0:80".to_string());
        let email = acme_email.clone().unwrap_or_else(|| {
            warn!("⚠️  --acme-email not set; using noreply@{}", base_domain);
            format!("noreply@{}", base_domain)
        });

        let cf_dns_token = std::env::var("MINIONS_CF_DNS_TOKEN").ok();
        if cf_dns_token.is_none() {
            warn!("⚠️  MINIONS_CF_DNS_TOKEN not set — wildcard cert provisioning will fail");
            warn!("   Set MINIONS_CF_DNS_TOKEN=<cloudflare-dns-api-token> for DNS-01 challenges");
        }

        let proxy_config = minions_proxy::ProxyConfig {
            db_path: db_path.clone(),
            domain: base_domain.clone(),
            api_key: api_key.clone(),
            certs_dir: "/var/lib/minions/certs".to_string(),
            cf_dns_token,
            acme_email: email,
            acme_staging,
            public_ip: public_ip.clone(),
        };

        info!("HTTPS proxy starting on https://{} + http://{} (domain: {})", https_addr, http_addr, base_domain);
        tokio::spawn(async move {
            if let Err(e) = minions_proxy::serve(proxy_config, &https_addr, &http_addr).await {
                tracing::error!("Proxy error: {:#}", e);
            }
        });
    } else {
        info!("HTTPS proxy disabled (use --proxy-bind, --http-bind, and --domain to enable)");
    }

    axum::serve(listener, app).await?;
    Ok(())
}
