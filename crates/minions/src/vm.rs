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
            
            // Validate SSH key format (basic sanity check)
            let pubkey = pubkey.trim();
            if !pubkey.starts_with("ssh-") && !pubkey.starts_with("ecdsa-") {
                anyhow::bail!("invalid SSH public key format (must start with ssh-* or ecdsa-*)");
            }
            if pubkey.contains('\n') || pubkey.contains('\r') {
                anyhow::bail!("SSH public key contains invalid newline characters");
            }

            // Use WriteFile request instead of shell interpolation to prevent injection
            let key_content = format!("{}\n", pubkey);
            agent::send_request(
                &vsock_socket,
                Request::WriteFile {
                    path: "/root/.ssh/authorized_keys".to_string(),
                    content: key_content,
                    mode: 0o600,
                    append: true,
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

/// Restart a running VM via the Cloud Hypervisor ACPI reset signal.
///
/// If the CH API call succeeds the VMM process stays alive and the guest
/// OS performs a clean reboot.  The agent will briefly become unreachable
/// during the reboot cycle; callers should not immediately issue agent
/// requests after this returns.
pub async fn restart(db_path: &str, name: &str) -> Result<db::Vm> {
    // Verify the VM exists and is running.
    {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?
            .with_context(|| format!("VM '{name}' not found"))?;
        if vm.status != "running" {
            anyhow::bail!("VM '{name}' is not running (status: {})", vm.status);
        }
        db::update_vm_status(&conn, name, "restarting", None)?;
    } // conn dropped

    // Send reboot signal.  If it fails we restore the running status and bail.
    if let Err(e) = hypervisor::reboot(name) {
        let conn = db::open(db_path)?;
        let _ = db::update_vm_status(&conn, name, "running", None);
        return Err(e);
    }

    // Mark running again — the VM stays alive, we just signalled a guest reboot.
    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, name, "running", None)?;
    db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' vanished after restart"))
}

/// Rename a stopped VM.
///
/// The VM **must** be stopped; renaming a running VM would leave socket paths
/// and TAP device names out of sync with the new name.
pub async fn rename(db_path: &str, old_name: &str, new_name: &str) -> Result<()> {
    validate_name(new_name)?;

    let (old_rootfs, old_tap) = {
        let conn = db::open(db_path)?;

        // Source must exist.
        let vm = db::get_vm(&conn, old_name)?
            .with_context(|| format!("VM '{old_name}' not found"))?;

        if vm.status != "stopped" {
            anyhow::bail!(
                "VM '{old_name}' must be stopped before renaming (status: {})",
                vm.status
            );
        }

        // Destination name must not exist.
        if db::get_vm(&conn, new_name)?.is_some() {
            anyhow::bail!("VM '{new_name}' already exists");
        }

        (vm.rootfs_path, vm.tap_device)
    };

    // Rename filesystem directory (rootfs lives at VMS_DIR/{name}/).
    let old_vm_dir = std::path::PathBuf::from(storage::VMS_DIR).join(old_name);
    let new_vm_dir = std::path::PathBuf::from(storage::VMS_DIR).join(new_name);
    if old_vm_dir.exists() {
        std::fs::rename(&old_vm_dir, &new_vm_dir)
            .with_context(|| format!("rename VM dir {:?} → {:?}", old_vm_dir, new_vm_dir))?;
    }

    // Rename TAP device (best-effort; may not exist if VM was already cleaned up).
    let new_tap = network::tap_name_for(new_name);
    let _ = std::process::Command::new("ip")
        .args(["link", "set", &old_tap, "name", &new_tap])
        .status();

    // Derive new path strings.
    let new_rootfs = old_rootfs.replace(old_name, new_name);
    let new_api_socket = hypervisor::api_socket_path(new_name);
    let new_vsock_socket = hypervisor::vsock_socket_path(new_name);

    let conn = db::open(db_path)?;
    db::rename_vm(
        &conn,
        old_name,
        new_name,
        &new_tap,
        &new_api_socket.to_string_lossy(),
        &new_vsock_socket.to_string_lossy(),
        &new_rootfs,
    )?;

    Ok(())
}

/// Copy an existing VM to a new VM.
///
/// Creates an independent copy of the source VM's rootfs, allocates fresh
/// network resources (IP, CID, TAP), and boots it.  The source VM may be
/// running or stopped.
pub async fn copy(
    db_path: &str,
    source_name: &str,
    new_name: &str,
    ssh_pubkey: Option<String>,
) -> Result<db::Vm> {
    validate_name(new_name)?;

    let (ip, vsock_socket, cfg) = {
        let conn = db::open(db_path)?;

        // Source must exist.
        let source = db::get_vm(&conn, source_name)?
            .with_context(|| format!("VM '{source_name}' not found"))?;

        // Destination must not exist.
        if db::get_vm(&conn, new_name)?.is_some() {
            anyhow::bail!("VM '{new_name}' already exists");
        }

        network::check_bridge().context("bridge check")?;
        hypervisor::ensure_run_dir()?;

        let ip = db::next_available_ip(&conn)?;
        let cid = db::next_available_cid(&conn)?;
        let mac = network::generate_mac(cid);
        let tap = network::create_tap(new_name).context("create TAP device")?;
        let rootfs = storage::copy_rootfs(source_name, new_name)
            .context("copy source rootfs")?;

        let api_socket = hypervisor::api_socket_path(new_name);
        let vsock_socket = hypervisor::vsock_socket_path(new_name);
        let serial_log = storage::serial_log_path(new_name);

        let vm_row = db::Vm {
            name: new_name.to_string(),
            status: "creating".to_string(),
            ip: ip.clone(),
            vsock_cid: cid,
            ch_pid: None,
            ch_api_socket: api_socket.to_string_lossy().to_string(),
            ch_vsock_socket: vsock_socket.to_string_lossy().to_string(),
            tap_device: tap.clone(),
            mac_address: mac.clone(),
            vcpus: source.vcpus,
            memory_mb: source.memory_mb,
            rootfs_path: rootfs.to_string_lossy().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            stopped_at: None,
        };
        db::insert_vm(&conn, &vm_row).context("insert copied VM into DB")?;

        let cfg = hypervisor::VmConfig {
            name: new_name.to_string(),
            vcpus: source.vcpus,
            memory_mb: source.memory_mb,
            mac,
            cid,
            rootfs,
            tap,
            api_socket,
            vsock_socket: vsock_socket.clone(),
            serial_log,
        };
        (ip, vsock_socket, cfg)
        // conn dropped
    };

    // Same async boot sequence as create().
    let result = async {
        let pid = hypervisor::spawn(&cfg).context("spawn cloud-hypervisor")?;
        info!("cloud-hypervisor PID={pid}");

        {
            let conn = db::open(db_path)?;
            db::update_vm_status(&conn, new_name, "starting", Some(pid as i64))?;
        }

        info!("waiting for agent to become ready…");
        agent::wait_ready(&vsock_socket, std::time::Duration::from_secs(60))
            .await
            .context("wait for agent ready")?;

        info!("configuring network for copied VM");
        agent::configure_network(
            &vsock_socket,
            &format!("{ip}/16"),
            "10.0.0.1",
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        )
        .await
        .context("configure guest network")?;

        if let Some(pubkey) = ssh_pubkey {
            let pubkey = pubkey.trim();
            if !pubkey.starts_with("ssh-") && !pubkey.starts_with("ecdsa-") {
                anyhow::bail!("invalid SSH public key format");
            }
            agent::send_request(
                &vsock_socket,
                Request::WriteFile {
                    path: "/root/.ssh/authorized_keys".to_string(),
                    content: format!("{}\n", pubkey),
                    mode: 0o600,
                    append: false, // overwrite — key came from current host user
                },
            )
            .await
            .context("inject SSH key into copied VM")?;
        }

        anyhow::Ok(())
    }
    .await;

    // Rollback on failure.
    if let Err(e) = result {
        info!("copy failed ({e:#}), rolling back…");
        let pid = {
            let conn = db::open(db_path).ok();
            conn.and_then(|c| db::get_vm(&c, new_name).ok().flatten())
                .and_then(|v| v.ch_pid)
        };
        let _ = hypervisor::shutdown(new_name, pid);
        let _ = network::destroy_tap(new_name);
        let _ = storage::destroy_rootfs(new_name);
        if let Ok(conn) = db::open(db_path) {
            let _ = db::delete_vm(&conn, new_name);
        }
        return Err(e);
    }

    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, new_name, "running", None)?;
    db::get_vm(&conn, new_name)?.with_context(|| format!("VM '{new_name}' vanished after copy"))
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
