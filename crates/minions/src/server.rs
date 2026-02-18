//! Daemon mode: startup reconciliation + HTTP server.

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

use crate::{api, auth, db, hypervisor, network};

/// Shared state passed to every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    /// Path to the SQLite database (each handler opens its own connection).
    pub db_path: Arc<String>,
    /// SSH public key to inject into new VMs.
    pub ssh_pubkey: Option<Arc<String>>,
    /// Authentication configuration.
    pub auth: auth::AuthConfig,
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
                    // Best-effort cleanup.
                    let _ = network::destroy_tap(&vm.name);
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

/// Start the HTTP API daemon.
pub async fn serve(db_path: String, bind: String, ssh_pubkey: Option<String>) -> Result<()> {
    reconcile(&db_path)?;

    // Load API key from environment variable
    let api_key = std::env::var("MINIONS_API_KEY").ok();
    if api_key.is_none() {
        warn!("⚠️  MINIONS_API_KEY not set — API authentication DISABLED (INSECURE)");
        warn!("   Set MINIONS_API_KEY=<secret> to enable authentication");
    } else {
        info!("✓ API authentication enabled");
    }

    let auth = auth::AuthConfig::new(api_key);

    let state = AppState {
        db_path: Arc::new(db_path),
        ssh_pubkey: ssh_pubkey.map(Arc::new),
        auth,
    };

    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;

    info!("minions daemon listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
