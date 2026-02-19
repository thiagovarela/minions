//! VM lifecycle orchestration with multi-host support.
//!
//! This module acts as a dispatcher: for VMs on the local host, it calls the
//! minions_node library directly (in-process). For VMs on remote hosts, it
//! makes HTTP calls via the host_client.

use anyhow::{Context, Result};

use crate::{db, host_client, scheduler};

/// Create a VM, dispatching to the appropriate host.
///
/// Uses the scheduler to select a host based on available capacity, then
/// either calls minions_node directly (local host) or makes an HTTP request
/// to a remote node agent.
pub async fn create(
    db_path: &str,
    name: &str,
    vcpus: u32,
    memory_mb: u32,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
) -> Result<db::Vm> {
    // Choose host via scheduler.
    let host_id = {
        let conn = db::open(db_path)?;
        scheduler::schedule(&conn, vcpus, memory_mb, scheduler::Strategy::BinPack)
            .context("schedule VM placement")?
    };

    // Dispatch based on host type.
    let host = {
        let conn = db::open(db_path)?;
        db::get_host(&conn, &host_id)?
            .with_context(|| format!("Host '{}' not found", host_id))?
    };

    if host.id == "local" {
        // Call minions_node library directly (in-process).
        minions_node::create(db_path, name, vcpus, memory_mb, ssh_pubkey.clone(), owner_id.clone()).await
    } else {
        // Make HTTP call to remote node agent.
        let client = host_client::HostClient::new(&host.address, host.api_port);
        let _response = client
            .create_vm(name, vcpus, memory_mb, ssh_pubkey, owner_id.clone())
            .await
            .context("remote create_vm call failed")?;

        // Fetch the VM record from the DB (the remote agent inserted it).
        let conn = db::open(db_path)?;
        db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found after remote creation", name))
    }
}

/// Stop a VM.
pub async fn stop(db_path: &str, name: &str) -> Result<db::Vm> {
    let host_id = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found", name))?;
        vm.host_id.unwrap_or_else(|| "local".to_string())
    };

    if host_id == "local" {
        minions_node::stop(db_path, name).await
    } else {
        let host = {
            let conn = db::open(db_path)?;
            db::get_host(&conn, &host_id)?
                .with_context(|| format!("Host '{}' not found", host_id))?
        };
        let client = host_client::HostClient::new(&host.address, host.api_port);
        let _response = client.stop_vm(name).await?;
        
        let conn = db::open(db_path)?;
        db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found after stop", name))
    }
}

/// Start a stopped VM.
pub async fn start(db_path: &str, name: &str) -> Result<db::Vm> {
    let host_id = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found", name))?;
        vm.host_id.unwrap_or_else(|| "local".to_string())
    };

    if host_id == "local" {
        minions_node::start(db_path, name).await
    } else {
        let host = {
            let conn = db::open(db_path)?;
            db::get_host(&conn, &host_id)?
                .with_context(|| format!("Host '{}' not found", host_id))?
        };
        let client = host_client::HostClient::new(&host.address, host.api_port);
        let _response = client.start_vm(name).await?;
        
        let conn = db::open(db_path)?;
        db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found after start", name))
    }
}

/// Restart a running VM.
pub async fn restart(db_path: &str, name: &str) -> Result<db::Vm> {
    let host_id = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found", name))?;
        vm.host_id.unwrap_or_else(|| "local".to_string())
    };

    if host_id == "local" {
        minions_node::restart(db_path, name).await
    } else {
        let host = {
            let conn = db::open(db_path)?;
            db::get_host(&conn, &host_id)?
                .with_context(|| format!("Host '{}' not found", host_id))?
        };
        let client = host_client::HostClient::new(&host.address, host.api_port);
        let _response = client.restart_vm(name).await?;
        
        let conn = db::open(db_path)?;
        db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found after restart", name))
    }
}

/// Destroy a VM.
pub async fn destroy(db_path: &str, name: &str) -> Result<()> {
    let host_id = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, name)?.with_context(|| format!("VM '{}' not found", name))?;
        vm.host_id.unwrap_or_else(|| "local".to_string())
    };

    if host_id == "local" {
        minions_node::destroy(db_path, name).await
    } else {
        let host = {
            let conn = db::open(db_path)?;
            db::get_host(&conn, &host_id)?
                .with_context(|| format!("Host '{}' not found", host_id))?
        };
        let client = host_client::HostClient::new(&host.address, host.api_port);
        client.destroy_vm(name).await?;
        Ok(())
    }
}

/// Resize a stopped VM's resources.
pub async fn resize(
    db_path: &str,
    name: &str,
    vcpus: Option<u32>,
    memory_mb: Option<u32>,
    disk_gb: Option<u32>,
) -> Result<db::Vm> {
    // Resize is always local for now (remote resizing requires additional API).
    minions_node::resize(db_path, name, vcpus, memory_mb, disk_gb).await
}

/// Rename a VM.
pub async fn rename(db_path: &str, old_name: &str, new_name: &str) -> Result<()> {
    // Rename is always local for now.
    minions_node::rename(db_path, old_name, new_name).await
}

/// Copy a VM.
pub async fn copy(
    db_path: &str,
    source_name: &str,
    new_name: &str,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
) -> Result<db::Vm> {
    // Copy is always local for now (cross-host copy requires additional work).
    minions_node::copy(db_path, source_name, new_name, ssh_pubkey, owner_id).await
}

/// List all VMs.
pub fn list(conn: &rusqlite::Connection) -> Result<Vec<db::Vm>> {
    minions_node::list(conn)
}

/// Create a snapshot.
pub async fn snapshot(
    db_path: &str,
    vm_name: &str,
    snap_name: Option<String>,
) -> Result<db::Snapshot> {
    let host_id = {
        let conn = db::open(db_path)?;
        let vm = db::get_vm(&conn, vm_name)?.with_context(|| format!("VM '{}' not found", vm_name))?;
        vm.host_id.unwrap_or_else(|| "local".to_string())
    };

    if host_id == "local" {
        minions_node::snapshot(db_path, vm_name, snap_name).await
    } else {
        let host = {
            let conn = db::open(db_path)?;
            db::get_host(&conn, &host_id)?
                .with_context(|| format!("Host '{}' not found", host_id))?
        };
        let client = host_client::HostClient::new(&host.address, host.api_port);
        let _response = client.snapshot_vm(vm_name, snap_name).await?;
        
        // TODO: Parse snapshot from response
        anyhow::bail!("Remote snapshot not fully implemented yet");
    }
}

/// List snapshots for a VM.
pub fn list_snapshots(db_path: &str, vm_name: &str) -> Result<Vec<db::Snapshot>> {
    minions_node::list_snapshots(db_path, vm_name)
}

/// Restore a VM from a snapshot.
pub async fn restore_snapshot(db_path: &str, vm_name: &str, snap_name: &str) -> Result<()> {
    minions_node::restore_snapshot(db_path, vm_name, snap_name).await
}

/// Delete a snapshot.
pub async fn delete_snapshot(db_path: &str, vm_name: &str, snap_name: &str) -> Result<()> {
    minions_node::delete_snapshot(db_path, vm_name, snap_name).await
}

/// Check quota for a user.
pub fn check_quota(
    conn: &rusqlite::Connection,
    owner_id: &str,
    requested_vcpus: u32,
    requested_memory_mb: u32,
) -> Result<()> {
    minions_node::check_quota(conn, owner_id, requested_vcpus, requested_memory_mb)
}

/// Maximum snapshots per VM.
pub const MAX_SNAPSHOTS_PER_VM: u32 = minions_node::MAX_SNAPSHOTS_PER_VM;
