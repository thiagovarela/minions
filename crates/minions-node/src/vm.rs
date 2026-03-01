//! VM lifecycle orchestration: create, destroy, list, status.

use anyhow::{Context, Result};
use chrono::Utc;
use std::time::Duration;
use tracing::info;

use minions_proto::Request;

use crate::{agent, db, hypervisor, network, storage};
use uuid::Uuid;

/// Create a fully networked VM.
///
/// Takes `db_path` instead of `&Connection` so the connection is never held
/// across `.await` points (rusqlite::Connection is !Sync).
///
/// `owner_id` — the SSH gateway user who owns this VM, or `None` for
/// admin/system VMs created directly via the HTTP API.
///
/// `os` — the operating system to use (defaults to Ubuntu if None).
pub async fn create(
    db_path: &str,
    name: &str,
    vcpus: u32,
    memory_mb: u32,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
) -> Result<db::Vm> {
    create_with_os(
        db_path,
        name,
        vcpus,
        memory_mb,
        ssh_pubkey,
        owner_id,
        storage::OsType::default(),
    )
    .await
}

/// Create a fully networked VM with a specific OS.
///
/// Takes `db_path` instead of `&Connection` so the connection is never held
/// across `.await` points (rusqlite::Connection is !Sync).
///
/// `owner_id` — the SSH gateway user who owns this VM, or `None` for
/// admin/system VMs created directly via the HTTP API.
///
/// `os` — the operating system to use for the VM image.
pub async fn create_with_os(
    db_path: &str,
    name: &str,
    vcpus: u32,
    memory_mb: u32,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
    os: storage::OsType,
) -> Result<db::Vm> {
    // ── Sync: validate + allocate resources ──────────────────────────────────
    let (ip, vsock_socket, cfg) = {
        let conn = db::open(db_path)?;
        validate_name(name)?;
        if db::get_vm(&conn, name)?.is_some() {
            anyhow::bail!("VM '{name}' already exists");
        }
        if let Some(ref oid) = owner_id {
            check_quota(&conn, oid, vcpus, memory_mb)?;
        }
        network::check_bridge().context("bridge check")?;
        hypervisor::ensure_run_dir()?;

        let ip = db::next_available_ip(&conn)?;
        let cid = db::next_available_cid(&conn)?;
        let mac = network::generate_mac(cid);
        let tap = network::create_tap(name).context("create TAP device")?;

        // Any failure after TAP creation must remove the TAP device.
        let rootfs = storage::create_rootfs_with_os(name, os)
            .context("copy base rootfs")
            .inspect_err(|_| {
                let _ = network::destroy_tap(name);
            })?;

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
            proxy_port: 80,
            proxy_public: false,
            owner_id: owner_id.clone(),
            host_id: Some("local".to_string()),
            os_type: os.as_str().to_string(),
        };
        db::insert_vm(&conn, &vm_row)
            .context("insert VM into DB")
            .inspect_err(|_| {
                let _ = network::destroy_tap(name);
                let _ = storage::destroy_rootfs(name);
            })?;

        let cfg = hypervisor::VmConfig {
            name: name.to_string(),
            vcpus,
            memory_mb,
            mac,
            cid,
            rootfs,
            kernel: os.kernel_path(),
            initramfs: os.initramfs_path(),
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

        // Inject the SSH gateway's proxy key so the gateway can SSH into this VM.
        inject_proxy_key(&vsock_socket).await;

        anyhow::Ok(())
    }
    .await;

    // ── Rollback on failure ───────────────────────────────────────────────────
    if let Err(e) = result {
        info!("create failed ({e:#}), rolling back…");
        let pid = {
            let conn = db::open(db_path).ok();
            conn.and_then(|c| db::get_vm(&c, name).ok().flatten())
                .and_then(|v| v.ch_pid)
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
    db::update_vm_status(&conn, name, "running", None).context("update VM status to running")?;
    db::get_vm(&conn, name)?.context("VM vanished after create")
}

/// Stop a running VM: shutdown CH process, remove TAP — but keep the rootfs
/// and DB record (status → "stopped").  The VM can later be destroyed.
///
/// This is useful before a rename or when you want to preserve the disk state.
pub async fn stop(db_path: &str, name: &str) -> Result<db::Vm> {
    // ── Sync: look up VM ─────────────────────────────────────────────────────
    let (ch_pid, api_socket, vsock_socket, tap_device) = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;
        if vm.status == "stopped" {
            anyhow::bail!("VM '{name}' is already stopped");
        }
        db::update_vm_status(&conn, name, "stopping", None)?;
        (
            vm.ch_pid,
            vm.ch_api_socket,
            vm.ch_vsock_socket,
            vm.tap_device,
        )
        // conn dropped here
    };

    // ── Shutdown CH process using stored socket paths ─────────────────────────
    hypervisor::shutdown_vm(&api_socket, &vsock_socket, ch_pid).context("shutdown hypervisor")?;
    network::destroy_tap_device(&tap_device).context("destroy TAP")?;

    // ── Mark stopped (keep DB record and rootfs) ──────────────────────────────
    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, name, "stopped", None)?;
    db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' vanished after stop"))
}

/// Start a stopped VM using its existing rootfs and stored configuration.
///
/// Recreates the TAP device (destroyed on stop), spawns cloud-hypervisor with
/// the original rootfs, reconfigures the guest network at the same IP, and
/// marks the VM as running.  The rootfs is preserved exactly as it was when
/// the VM was stopped — no data is lost.
pub async fn start(db_path: &str, name: &str) -> Result<db::Vm> {
    // ── Sync: validate + build config from stored state ───────────────────────
    let (ip, vsock_socket, tap, cfg) = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;

        if vm.status != "stopped" {
            anyhow::bail!("VM '{name}' is not stopped (status: {})", vm.status);
        }

        network::check_bridge().context("bridge check")?;
        hypervisor::ensure_run_dir()?;

        // Re-create TAP using the stored device name (handles renames correctly).
        let tap = network::create_tap_named(&vm.tap_device)
            .with_context(|| format!("recreate TAP device '{}'", vm.tap_device))?;

        let serial_log = storage::serial_log_path(name);
        let api_socket = std::path::PathBuf::from(&vm.ch_api_socket);
        let vsock_socket = std::path::PathBuf::from(&vm.ch_vsock_socket);

        let os_type = storage::OsType::from_str(&vm.os_type)
            .unwrap_or_else(|_| storage::OsType::default());

        let cfg = hypervisor::VmConfig {
            name: name.to_string(),
            vcpus: vm.vcpus,
            memory_mb: vm.memory_mb,
            mac: vm.mac_address.clone(),
            cid: vm.vsock_cid,
            rootfs: std::path::PathBuf::from(&vm.rootfs_path),
            kernel: os_type.kernel_path(),
            initramfs: os_type.initramfs_path(),
            tap: tap.clone(),
            api_socket,
            vsock_socket: vsock_socket.clone(),
            serial_log,
        };

        db::update_vm_status(&conn, name, "starting", None)?;

        (vm.ip.clone(), vsock_socket, tap, cfg)
        // conn dropped here
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

        info!("agent ready, reconfiguring network at {ip}");
        agent::configure_network(
            &vsock_socket,
            &format!("{ip}/16"),
            "10.0.0.1",
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
        )
        .await
        .context("configure guest network")?;

        anyhow::Ok(())
    }
    .await;

    // ── Rollback on failure ───────────────────────────────────────────────────
    if let Err(e) = result {
        info!("start failed ({e:#}), rolling back…");
        let pid = {
            let conn = db::open(db_path).ok();
            conn.and_then(|c| db::get_vm(&c, name).ok().flatten())
                .and_then(|v| v.ch_pid)
        };
        let _ = hypervisor::shutdown(name, pid);
        let _ = network::destroy_tap_device(&tap);
        if let Ok(conn) = db::open(db_path) {
            let _ = db::update_vm_status(&conn, name, "stopped", None);
        }
        return Err(e);
    }

    // ── Mark running ──────────────────────────────────────────────────────────
    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, name, "running", None)?;
    db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' vanished after start"))
}

/// Destroy a VM: shutdown CH, delete TAP, delete rootfs, remove DB row.
///
/// Uses stored socket and TAP paths from the DB so it works correctly even
/// after a rename.
pub async fn destroy(db_path: &str, name: &str) -> Result<()> {
    // ── Sync: look up VM, collect stored paths ────────────────────────────────
    let (ch_pid, api_socket, vsock_socket, tap_device) = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;
        db::update_vm_status(&conn, name, "stopping", None)?;
        (
            vm.ch_pid,
            vm.ch_api_socket,
            vm.ch_vsock_socket,
            vm.tap_device,
        )
        // conn dropped here
    };

    // ── Shutdown CH using stored socket paths ─────────────────────────────────
    hypervisor::shutdown_vm(&api_socket, &vsock_socket, ch_pid).context("shutdown hypervisor")?;
    network::destroy_tap_device(&tap_device).context("destroy TAP")?;
    storage::destroy_rootfs(name).context("destroy rootfs")?;

    // ── Delete all snapshots (files + DB records) ─────────────────────────────
    // Best-effort: log errors but don't fail the destroy.
    if let Err(e) = storage::delete_all_snapshot_files(name) {
        tracing::warn!("failed to delete snapshot files for VM '{}': {:#}", name, e);
    }

    // ── Remove DB record ──────────────────────────────────────────────────────
    let conn = db::open(db_path)?;
    db::delete_all_snapshots(&conn, name)?;
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
    // Verify the VM exists and is running; capture stored socket path.
    let api_socket = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;
        if vm.status != "running" {
            anyhow::bail!("VM '{name}' is not running (status: {})", vm.status);
        }
        db::update_vm_status(&conn, name, "restarting", None)?;
        vm.ch_api_socket
    }; // conn dropped

    // Flush all guest filesystem writes before the ACPI reset.
    // The ACPI reboot sends a hardware reset signal; without an explicit sync
    // the guest page cache may not be flushed in time, losing recent writes
    // (e.g. SSH authorized_keys injected during create).
    let vsock_path_for_sync = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;
        std::path::PathBuf::from(vm.ch_vsock_socket)
    };
    let _ = agent::send_request(
        &vsock_path_for_sync,
        Request::Exec {
            command: "sync".to_string(),
            args: vec![],
        },
    )
    .await;

    // Send reboot signal using stored socket path.
    // If it fails we restore the running status and bail.
    if let Err(e) = hypervisor::reboot(&api_socket) {
        let conn = db::open(db_path)?;
        let _ = db::update_vm_status(&conn, name, "running", None);
        return Err(e);
    }

    // Wait for the agent to come back up after the guest reboot.
    // The guest OS takes a few seconds to reboot; without this wait, any
    // operation immediately after restart (exec, status) would fail.
    let vsock_socket = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?
            .with_context(|| format!("VM '{name}' vanished after reboot signal"))?;
        std::path::PathBuf::from(vm.ch_vsock_socket)
    };
    agent::wait_ready(&vsock_socket, Duration::from_secs(60))
        .await
        .context("agent did not come back after restart")?;

    // Mark running again.
    let conn = db::open(db_path)?;
    db::update_vm_status(&conn, name, "running", None)?;
    db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' vanished after restart"))
}

/// Resize a stopped VM's resources (CPU, memory, disk).
///
/// The VM **must be stopped** before resizing. On the next `start`, Cloud
/// Hypervisor will use the updated values from the DB.
///
/// Disk resizing uses `truncate` and `resize2fs` to grow the ext4 image.
/// Disk can only be grown, not shrunk.
pub async fn resize(
    db_path: &str,
    name: &str,
    vcpus: Option<u32>,
    memory_mb: Option<u32>,
    disk_gb: Option<u32>,
) -> Result<db::Vm> {
    // Validate at least one field is being updated
    if vcpus.is_none() && memory_mb.is_none() && disk_gb.is_none() {
        anyhow::bail!("at least one of vcpus, memory_mb, or disk_gb must be specified");
    }

    // ── Sync: validate VM state and values ───────────────────────────────────
    let rootfs_path = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' not found"))?;

        if vm.status != "stopped" {
            anyhow::bail!(
                "VM '{name}' must be stopped before resizing (current status: {})",
                vm.status
            );
        }

        // Validate resource values
        if let Some(v) = vcpus {
            if !(1..=16).contains(&v) {
                anyhow::bail!("vcpus must be between 1 and 16 (got {})", v);
            }
        }
        if let Some(m) = memory_mb {
            if !(128..=16384).contains(&m) {
                anyhow::bail!("memory_mb must be between 128 and 16384 (got {})", m);
            }
        }

        // Check quota if VM has an owner
        if let Some(ref owner_id) = vm.owner_id {
            let (_, plan) = db::get_user_plan(&conn, owner_id)?;
            let mut usage = db::get_user_usage(&conn, owner_id)?;

            // Subtract current VM's resources from usage before checking new limits
            usage.total_vcpus = usage.total_vcpus.saturating_sub(vm.vcpus);
            usage.total_memory_mb = usage.total_memory_mb.saturating_sub(vm.memory_mb);

            // Add new resources
            let new_vcpus = vcpus.unwrap_or(vm.vcpus);
            let new_memory = memory_mb.unwrap_or(vm.memory_mb);

            if usage.total_vcpus + new_vcpus > plan.max_vcpus {
                anyhow::bail!(
                    "resizing would exceed vCPU quota: {} + {} > {} (plan: {})",
                    usage.total_vcpus,
                    new_vcpus,
                    plan.max_vcpus,
                    plan.name
                );
            }
            if usage.total_memory_mb + new_memory > plan.max_memory_mb {
                anyhow::bail!(
                    "resizing would exceed memory quota: {} + {} > {} MB (plan: {})",
                    usage.total_memory_mb,
                    new_memory,
                    plan.max_memory_mb,
                    plan.name
                );
            }
        }

        vm.rootfs_path.clone()
        // conn dropped here
    };

    // ── Disk resize (if requested) ────────────────────────────────────────────
    if let Some(new_disk_gb) = disk_gb {
        storage::resize_rootfs(&rootfs_path, new_disk_gb).context("resize rootfs")?;
    }

    // ── Update DB (CPU/memory) ────────────────────────────────────────────────
    {
        let conn = db::open(db_path)?;
        db::set_vm_resources(&conn, name, vcpus, memory_mb)?;
    }

    // ── Return updated VM record ──────────────────────────────────────────────
    let conn = db::open(db_path)?;
    db::get_vm(&conn, name)?.with_context(|| format!("VM '{name}' vanished after resize"))
}

/// Rename a VM.
///
/// Works on VMs in **any** state (running or stopped).
///
/// All resource paths (sockets, TAP, rootfs) are stored in the DB, so
/// subsequent operations (destroy, exec, stop) always use those stored paths
/// and are unaffected by a name-only rename of a running VM.
///
/// For stopped VMs we also opportunistically rename the rootfs directory and
/// TAP device to keep paths consistent with the new name, and update the
/// stored paths in the DB accordingly.
pub async fn rename(db_path: &str, old_name: &str, new_name: &str) -> Result<()> {
    validate_name(new_name)?;

    let (status, old_rootfs, old_tap) = {
        let conn = db::open(db_path)?;

        // Source must exist.
        let vm =
            db::get_vm(&conn, old_name)?.with_context(|| format!("VM '{old_name}' not found"))?;

        // Destination name must not exist.
        if db::get_vm(&conn, new_name)?.is_some() {
            anyhow::bail!("VM '{new_name}' already exists");
        }

        (vm.status, vm.rootfs_path, vm.tap_device)
    };

    // For stopped VMs: also rename the rootfs directory and TAP device so
    // stored paths stay consistent with the new name.
    let (new_tap, new_api_socket, new_vsock_socket, new_rootfs) = if status == "stopped" {
        let old_vm_dir = std::path::PathBuf::from(storage::VMS_DIR).join(old_name);
        let new_vm_dir = std::path::PathBuf::from(storage::VMS_DIR).join(new_name);
        if old_vm_dir.exists() {
            std::fs::rename(&old_vm_dir, &new_vm_dir)
                .with_context(|| format!("rename VM dir {:?} → {:?}", old_vm_dir, new_vm_dir))?;
        }

        let new_tap = network::tap_name_for(new_name);
        let _ = std::process::Command::new("ip")
            .args(["link", "set", &old_tap, "name", &new_tap])
            .status();

        let new_rootfs = old_rootfs.replace(old_name, new_name);
        let new_api = hypervisor::api_socket_path(new_name)
            .to_string_lossy()
            .to_string();
        let new_vsock = hypervisor::vsock_socket_path(new_name)
            .to_string_lossy()
            .to_string();
        (new_tap, new_api, new_vsock, new_rootfs)
    } else {
        // Running VM: keep all stored paths unchanged; only the name changes.
        (old_tap, String::new(), String::new(), old_rootfs)
    };

    let conn = db::open(db_path)?;
    if status == "stopped" {
        db::rename_vm(
            &conn,
            old_name,
            new_name,
            &new_tap,
            &new_api_socket,
            &new_vsock_socket,
            &new_rootfs,
        )?;
    } else {
        // Only update the name; leave all path columns intact.
        db::rename_vm_name_only(&conn, old_name, new_name)?;
    }

    Ok(())
}

/// Copy an existing VM to a new VM.
///
/// Creates an independent copy of the source VM's rootfs, allocates fresh
/// network resources (IP, CID, TAP), and boots it.  The source VM may be
/// running or stopped.
///
/// `owner_id` — the user who will own the new copy (typically the same user
/// who owns the source, but the caller decides).
pub async fn copy(
    db_path: &str,
    source_name: &str,
    new_name: &str,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
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
        if let Some(ref oid) = owner_id {
            check_quota(&conn, oid, source.vcpus, source.memory_mb)?;
        }

        network::check_bridge().context("bridge check")?;
        hypervisor::ensure_run_dir()?;

        let ip = db::next_available_ip(&conn)?;
        let cid = db::next_available_cid(&conn)?;
        let mac = network::generate_mac(cid);
        let tap = network::create_tap(new_name).context("create TAP device")?;

        // Any failure after TAP creation must remove the TAP device.
        let rootfs = storage::copy_rootfs(&source.rootfs_path, new_name)
            .context("copy source rootfs")
            .inspect_err(|_| {
                let _ = network::destroy_tap(new_name);
            })?;

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
            // Inherit proxy settings and OS type from source VM.
            proxy_port: source.proxy_port,
            proxy_public: source.proxy_public,
            owner_id: owner_id.clone(),
            host_id: Some("local".to_string()),
            os_type: source.os_type.clone(),
        };
        db::insert_vm(&conn, &vm_row)
            .context("insert copied VM into DB")
            .inspect_err(|_| {
                let _ = network::destroy_tap(new_name);
                let _ = storage::destroy_rootfs(new_name);
            })?;

        let os_type = storage::OsType::from_str(&source.os_type)
            .unwrap_or_else(|_| storage::OsType::default());

        let cfg = hypervisor::VmConfig {
            name: new_name.to_string(),
            vcpus: source.vcpus,
            memory_mb: source.memory_mb,
            mac,
            cid,
            rootfs,
            kernel: os_type.kernel_path(),
            initramfs: os_type.initramfs_path(),
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

        // Inject the SSH gateway's proxy key.
        inject_proxy_key(&vsock_socket).await;

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

// ── Snapshots ─────────────────────────────────────────────────────────────────

/// Maximum number of snapshots per VM. Attempting to create more returns an error.
pub const MAX_SNAPSHOTS_PER_VM: u32 = 10;

/// Create a disk-only snapshot of a VM.
///
/// If the VM is running, it is briefly paused (vCPUs + I/O suspended) while
/// the rootfs is copied, then resumed. If the VM is stopped, the copy happens
/// without pausing.
///
/// `snap_name` — user-provided name, or a timestamp if None.
pub async fn snapshot(
    db_path: &str,
    vm_name: &str,
    snap_name: Option<String>,
) -> Result<db::Snapshot> {
    // ── Resolve snapshot name ─────────────────────────────────────────────────
    let snap_name =
        snap_name.unwrap_or_else(|| chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string());
    validate_snapshot_name(&snap_name)?;

    // ── Look up VM and check limits ───────────────────────────────────────────
    let (status, api_socket, rootfs_path) = {
        let conn = db::open(db_path)?;
        let vm =
            db::get_vm(&conn, vm_name)?.with_context(|| format!("VM '{vm_name}' not found"))?;
        if vm.status == "creating" || vm.status == "starting" {
            anyhow::bail!("VM '{vm_name}' is still starting — wait until it is running or stopped");
        }
        if db::get_snapshot(&conn, vm_name, &snap_name)?.is_some() {
            anyhow::bail!("snapshot '{snap_name}' already exists for VM '{vm_name}'");
        }
        let count = db::count_snapshots(&conn, vm_name)?;
        if count >= MAX_SNAPSHOTS_PER_VM {
            anyhow::bail!(
                "snapshot limit reached ({count}/{MAX_SNAPSHOTS_PER_VM}) for VM '{vm_name}'. \
                 Delete an existing snapshot first."
            );
        }
        (vm.status, vm.ch_api_socket, vm.rootfs_path)
    };

    // ── Pause running VM, copy rootfs, resume ────────────────────────────────
    let was_running = status == "running";
    if was_running {
        // Flush guest page cache before pausing.
        let vsock_socket = {
            let conn = db::open(db_path)?;
            let vm = db::get_vm(&conn, vm_name)?.unwrap();
            std::path::PathBuf::from(vm.ch_vsock_socket)
        };
        let _ = agent::send_request(
            &vsock_socket,
            minions_proto::Request::Exec {
                command: "sync".to_string(),
                args: vec![],
            },
        )
        .await;

        hypervisor::pause_vm(&api_socket)
            .with_context(|| format!("pause VM '{vm_name}' before snapshot"))?;
        info!("VM '{vm_name}' paused for snapshot");
    }

    let copy_result = tokio::task::spawn_blocking({
        let rootfs_path = rootfs_path.clone();
        let vm_name = vm_name.to_string();
        let snap_name = snap_name.clone();
        move || storage::create_snapshot(&rootfs_path, &vm_name, &snap_name)
    })
    .await
    .context("snapshot copy task panicked")?;

    if was_running {
        // Always resume, even if the copy failed.
        if let Err(e) = hypervisor::resume_vm(&api_socket) {
            tracing::error!("failed to resume VM '{vm_name}' after snapshot: {:#}", e);
        } else {
            info!("VM '{vm_name}' resumed after snapshot");
        }
    }

    let (_snap_path, size_bytes) = copy_result.context("create snapshot files")?;

    // ── Record snapshot in DB ─────────────────────────────────────────────────
    let snap = db::Snapshot {
        id: Uuid::new_v4().to_string(),
        vm_name: vm_name.to_string(),
        name: snap_name,
        size_bytes: Some(size_bytes),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let conn = db::open(db_path)?;
    db::insert_snapshot(&conn, &snap)?;
    Ok(snap)
}

/// List all snapshots for a VM.
pub fn list_snapshots(db_path: &str, vm_name: &str) -> Result<Vec<db::Snapshot>> {
    let conn = db::open(db_path)?;
    // Verify VM exists.
    db::get_vm(&conn, vm_name)?.with_context(|| format!("VM '{vm_name}' not found"))?;
    db::list_snapshots(&conn, vm_name)
}

/// Restore a VM from a snapshot.
///
/// The VM **must be stopped** before restoring. This overwrites the VM's
/// current rootfs with the snapshot copy.
pub async fn restore_snapshot(db_path: &str, vm_name: &str, snap_name: &str) -> Result<()> {
    // ── Validate state ────────────────────────────────────────────────────────
    let rootfs_path = {
        let conn = db::open(db_path)?;
        let vm =
            db::get_vm(&conn, vm_name)?.with_context(|| format!("VM '{vm_name}' not found"))?;
        if vm.status != "stopped" {
            anyhow::bail!(
                "VM '{vm_name}' must be stopped before restoring a snapshot (status: {}). \
                 Run: minions stop {vm_name}",
                vm.status
            );
        }
        // Verify snapshot exists.
        db::get_snapshot(&conn, vm_name, snap_name)?
            .with_context(|| format!("snapshot '{snap_name}' not found for VM '{vm_name}'"))?;
        vm.rootfs_path
    };

    // ── Copy snapshot rootfs over VM rootfs ───────────────────────────────────
    let rootfs = rootfs_path.clone();
    let vn = vm_name.to_string();
    let sn = snap_name.to_string();
    tokio::task::spawn_blocking(move || storage::restore_snapshot(&rootfs, &vn, &sn))
        .await
        .context("restore snapshot task panicked")?
        .context("restore snapshot files")?;

    info!("VM '{vm_name}' restored from snapshot '{snap_name}'");
    Ok(())
}

/// Delete a snapshot (files + DB record).
pub async fn delete_snapshot(db_path: &str, vm_name: &str, snap_name: &str) -> Result<()> {
    let conn = db::open(db_path)?;
    db::get_vm(&conn, vm_name)?.with_context(|| format!("VM '{vm_name}' not found"))?;
    db::get_snapshot(&conn, vm_name, snap_name)?
        .with_context(|| format!("snapshot '{snap_name}' not found for VM '{vm_name}'"))?;

    // Delete files first, then DB record.
    let vn = vm_name.to_string();
    let sn = snap_name.to_string();
    tokio::task::spawn_blocking(move || storage::delete_snapshot_files(&vn, &sn))
        .await
        .context("delete snapshot task panicked")?
        .context("delete snapshot files")?;

    db::delete_snapshot(&conn, vm_name, snap_name)?;
    info!("snapshot '{snap_name}' deleted for VM '{vm_name}'");
    Ok(())
}

// ── Quota enforcement ─────────────────────────────────────────────────────────

/// Check whether `owner_id` can create a VM with the given resource request.
///
/// Looks up their plan limits and compares against live usage.
/// Returns `Ok(())` if within limits, or a descriptive error message.
/// Passes silently for admin VMs (no `owner_id`).
pub fn check_quota(
    conn: &rusqlite::Connection,
    owner_id: &str,
    requested_vcpus: u32,
    requested_memory_mb: u32,
) -> Result<()> {
    let (_, plan) = db::get_user_plan(conn, owner_id)?;
    let usage = db::get_user_usage(conn, owner_id)?;

    if usage.vm_count >= plan.max_vms {
        anyhow::bail!(
            "VM limit reached ({}/{}). Destroy or stop an existing VM, or upgrade your plan.",
            usage.vm_count,
            plan.max_vms
        );
    }
    if usage.total_vcpus + requested_vcpus > plan.max_vcpus {
        anyhow::bail!(
            "vCPU limit would be exceeded ({} + {} > {}). Stop a VM or upgrade your plan.",
            usage.total_vcpus,
            requested_vcpus,
            plan.max_vcpus
        );
    }
    if usage.total_memory_mb + requested_memory_mb > plan.max_memory_mb {
        anyhow::bail!(
            "Memory limit would be exceeded ({} MiB + {} MiB > {} MiB). Stop a VM or upgrade your plan.",
            usage.total_memory_mb,
            requested_memory_mb,
            plan.max_memory_mb
        );
    }
    Ok(())
}

fn validate_snapshot_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("snapshot name cannot be empty");
    }
    if name.len() > 64 {
        anyhow::bail!("snapshot name must be 64 characters or fewer");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!(
            "snapshot name must only contain alphanumeric characters, hyphens, underscores, and dots"
        );
    }
    Ok(())
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

/// Inject the SSH gateway's proxy public key into the VM's authorized_keys.
///
/// This allows the SSH gateway to authenticate as root when proxying SSH
/// connections (`ssh vmname@ssh.miniclankers.com`).
///
/// The proxy key is read from `/var/lib/minions/proxy_key.pub` (created by
/// `minions serve --ssh-bind` on first run). If the file doesn't exist yet,
/// this is a no-op with a warning.
async fn inject_proxy_key(vsock_socket: &std::path::Path) {
    let pub_path = minions_ssh::PROXY_PUBKEY_PATH;
    let pubkey = match std::fs::read_to_string(pub_path) {
        Ok(k) => k.trim().to_string(),
        Err(_) => {
            tracing::warn!(
                "proxy key not found at {} — SSH gateway proxy mode will not work for this VM\n\
                 Run `minions serve --ssh-bind 0.0.0.0:22` at least once to generate it,\n\
                 then recreate the VM.",
                pub_path
            );
            return;
        }
    };

    let result = agent::send_request(
        vsock_socket,
        Request::WriteFile {
            path: "/root/.ssh/authorized_keys".to_string(),
            content: format!("{}\n", pubkey),
            mode: 0o600,
            append: true,
        },
    )
    .await;

    match result {
        Ok(_) => tracing::info!("✓ injected proxy key into VM"),
        Err(e) => tracing::warn!("failed to inject proxy key: {}", e),
    }
}
