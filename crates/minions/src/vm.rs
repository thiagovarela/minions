//! VM lifecycle orchestration: create, destroy, list, status.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::Connection;
use std::time::Duration;
use tracing::info;

use crate::{agent, db, hypervisor, network, storage};

/// Create a fully networked VM.
pub async fn create(conn: &Connection, name: &str, vcpus: u32, memory_mb: u32) -> Result<db::Vm> {
    validate_name(name)?;

    if db::get_vm(conn, name)?.is_some() {
        anyhow::bail!("VM '{name}' already exists");
    }

    network::check_bridge().context("bridge check")?;
    hypervisor::ensure_run_dir()?;

    // Allocate resources.
    let ip = db::next_available_ip(conn)?;
    let cid = db::next_available_cid(conn)?;
    let mac = network::generate_mac(cid);
    let tap = network::create_tap(name).context("create TAP device")?;
    let rootfs = storage::create_rootfs(name).context("copy base rootfs")?;

    let api_socket = hypervisor::api_socket_path(name);
    let vsock_socket = hypervisor::vsock_socket_path(name);
    let serial_log = storage::serial_log_path(name);

    let vm = db::Vm {
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

    db::insert_vm(conn, &vm).context("insert VM into DB")?;

    // Spawn cloud-hypervisor.
    let cfg = hypervisor::VmConfig {
        name: name.to_string(),
        vcpus,
        memory_mb,
        mac,
        cid,
        rootfs: rootfs.clone(),
        tap,
        api_socket: api_socket.clone(),
        vsock_socket: vsock_socket.clone(),
        serial_log,
    };

    let pid = hypervisor::spawn(&cfg).context("spawn cloud-hypervisor")?;
    info!("cloud-hypervisor PID={pid}");

    db::update_vm_status(conn, name, "starting", Some(pid as i64))
        .context("update VM status to starting")?;

    // Wait for agent to be ready (up to 60 seconds).
    info!("waiting for agent to become ready…");
    agent::wait_ready(&vsock_socket, Duration::from_secs(60))
        .await
        .context("wait for agent ready")?;

    info!("agent ready, configuring network");

    // Configure guest networking.
    agent::configure_network(
        &vsock_socket,
        &format!("{ip}/16"),
        "10.0.0.1",
        vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
    )
    .await
    .context("configure guest network")?;

    db::update_vm_status(conn, name, "running", None).context("update VM status to running")?;

    let vm = db::get_vm(conn, name)?.expect("VM just inserted");
    Ok(vm)
}

/// Destroy a VM: shutdown CH, delete TAP, delete rootfs, remove DB row.
pub async fn destroy(conn: &Connection, name: &str) -> Result<()> {
    let vm = db::get_vm(conn, name)?
        .with_context(|| format!("VM '{name}' not found"))?;

    db::update_vm_status(conn, name, "stopping", None)?;

    // Graceful CH shutdown.
    hypervisor::shutdown(name, vm.ch_pid).context("shutdown hypervisor")?;

    // Tear down networking.
    network::destroy_tap(name).context("destroy TAP")?;

    // Remove rootfs.
    storage::destroy_rootfs(name).context("destroy rootfs")?;

    // Remove DB record.
    db::delete_vm(conn, name)?;

    Ok(())
}

/// List all VMs, correcting stale "running" status for dead processes.
pub fn list(conn: &Connection) -> Result<Vec<db::Vm>> {
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
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        anyhow::bail!("VM name must only contain alphanumeric characters and hyphens");
    }
    Ok(())
}
