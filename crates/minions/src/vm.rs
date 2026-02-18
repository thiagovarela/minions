//! VM lifecycle orchestration: create, destroy, list, status.

use anyhow::{Context, Result};
use chrono::Utc;
use std::time::Duration;
use tracing::info;

use minions_proto::Request;

use crate::{agent, db, hypervisor, network, storage};

/// Create a fully networked VM.
///
/// Takes `db_path` instead of `&Connection` so the connection is never held
/// across `.await` points (rusqlite::Connection is !Sync).
pub async fn create(
    db_path: &str,
    name: &str,
    vcpus: u32,
    memory_mb: u32,
    ssh_pubkey: Option<String>,
) -> Result<db::Vm> {
    // ── Sync: validate + allocate resources ──────────────────────────────────
    let (ip, vsock_socket, cfg) = {
        let conn = db::open(db_path)?;
        validate_name(name)?;
        if db::get_vm(&conn, name)?.is_some() {
            anyhow::bail!("VM '{name}' already exists");
        }
        network::check_bridge().context("bridge check")?;
        hypervisor::ensure_run_dir()?;

        let ip = db::next_available_ip(&conn)?;
        let cid = db::next_available_cid(&conn)?;
        let mac = network::generate_mac(cid);
        let tap = network::create_tap(name).context("create TAP device")?;
        let rootfs = storage::create_rootfs(name).context("copy base rootfs")?;

        let api_socket = hypervisor::api_socket_path(name);
        let vsock_socket = hypervisor::vsock_socket_path(name);
        let serial_log = storage::serial_log_path(name);

        let vm_row = db::Vm {
            name: name.to_string(),
            status: "creating".to_string(),
            ip: ip.clone(),
            vsock_cid: cid,
            ch_pid: None,
            ch_api_socket: api_socket.to_string_lossy().to_string(),
            ch_vsock_socket: vsock_socket.to_string_lossy().to_string(),
            tap_device: tap.clone(),
            mac_address: mac.clone(),
            vcpus,
            memory_mb,
            rootfs_path: rootfs.to_string_lossy().to_string(),
            created_at: Utc::now().to_rfc3339(),
            stopped_at: None,
        };
        db::insert_vm(&conn, &vm_row).context("insert VM into DB")?;

        let cfg = hypervisor::VmConfig {
            name: name.to_string(),
            vcpus,
            memory_mb,
            mac,
            cid,
            rootfs,
            tap,
            api_socket,
            vsock_socket: vsock_socket.clone(),
            serial_log,
        };
        (ip, vsock_socket, cfg)
        // conn dropped here — no borrow across await
    };

    // ── Async: spawn CH, wait for agent, configure network ───────────────────
    let result = async {
        let pid = hypervisor::spawn(&cfg).context("spawn cloud-hypervisor")?;
        info!("cloud-hypervisor PID={pid}");

        {
            let conn = db::open(db_path)?;
            db::update_vm_status(&conn, name, "starting", Some(pid as i64))?;
        }

        info!("waiting for agent to become ready…");
        agent::wait_ready(&vsock_socket, Duration::from_secs(60))
            .await
            .context("wait for agent ready")?;

        info!("agent ready, configuring network");
        agent::configure_network(
            &vsock_socket,
            &format!("{ip}/16"),
            "10.0.0.1",
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        )
        .await
        .context("configure guest network")?;

        if let Some(pubkey) = ssh_pubkey {
            info!("injecting SSH public key into VM");
            let script = format!(
                "mkdir -p /root/.ssh && chmod 700 /root/.ssh && \
                 echo '{pubkey}' >> /root/.ssh/authorized_keys && \
                 chmod 600 /root/.ssh/authorized_keys"
            );
            agent::send_request(
                &vsock_socket,
                Request::Exec {
                    command: "sh".to_string(),
                    args: vec!["-c".to_string(), script],
                },
            )
            .await
            .context("inject SSH key")?;
        }

        anyhow::Ok(())
    }
    .await;

    // ── Rollback on failure ───────────────────────────────────────────────────
    if let Err(e) = result {
        info!("create failed ({e:#}), rolling back…");
        let pid = {
            let conn = db::open(db_path).ok();
            conn.and_then(|c| db::get_vm(&c, name).ok().flatten()).and_then(|v| v.ch_pid)
        };
        let _ = hypervisor::shutdown(name, pid);
        let _ = network::destroy_tap(name);
        let _ = storage::destroy_rootfs(name);
        if let Ok(conn) = db::open(db_path) {
            let _ = db::delete_vm(&conn, name);
        }
        return Err(e);
    }

    // ── Sync: mark running, return record ────────────────────────────────────
    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, name, "running", None)
        .context("update VM status to running")?;
    db::get_vm(&conn, name)?.context("VM vanished after create")
}

/// Destroy a VM: shutdown CH, delete TAP, delete rootfs, remove DB row.
pub async fn destroy(db_path: &str, name: &str) -> Result<()> {
    // ── Sync: look up VM ─────────────────────────────────────────────────────
    let ch_pid = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?
            .with_context(|| format!("VM '{name}' not found"))?;
        db::update_vm_status(&conn, name, "stopping", None)?;
        vm.ch_pid
        // conn dropped here
    };

    // ── Sync (blocking but not holding connection): shutdown CH ──────────────
    hypervisor::shutdown(name, ch_pid).context("shutdown hypervisor")?;
    network::destroy_tap(name).context("destroy TAP")?;
    storage::destroy_rootfs(name).context("destroy rootfs")?;

    // ── Sync: remove DB record ───────────────────────────────────────────────
    let conn = db::open(db_path)?;
    db::delete_vm(&conn, name)?;
    Ok(())
}

/// List all VMs, correcting stale "running" status for dead processes.
pub fn list(conn: &rusqlite::Connection) -> Result<Vec<db::Vm>> {
    let mut vms = db::list_vms(conn)?;
    for vm in &mut vms {
        if vm.status == "running" && !hypervisor::is_alive_pid(vm.ch_pid) {
            vm.status = "error (process dead)".to_string();
            let _ = db::update_vm_status(conn, &vm.name, "error", None);
        }
    }
    Ok(vms)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("VM name cannot be empty");
    }
    if name.len() > 11 {
        anyhow::bail!("VM name must be 11 characters or fewer (TAP device limit)");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("VM name must only contain alphanumeric characters and hyphens");
    }
    Ok(())
}
