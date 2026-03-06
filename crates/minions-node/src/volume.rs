//! Volume lifecycle management for VMs
//!
//! Handles opening volumes, starting NBD servers, and connecting them to VMs.

use anyhow::{Context, Result};
use minions_db as db;
use minions_volume::{VolumeConfig, VolumeHandle};
use minions_volume::s3::S3Config;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::storage;

/// Global registry of active volume handles
/// Maps volume name -> VolumeHandle
use once_cell::sync::Lazy;

static VOLUME_REGISTRY: Lazy<Mutex<HashMap<String, Arc<VolumeHandle>>>> = 
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Open a volume and start its NBD server
pub async fn open_volume(volume_name: &str, s3_config: S3Config) -> Result<Arc<VolumeHandle>> {
    info!("Opening volume '{}'", volume_name);

    // Check if already open
    {
        let registry = VOLUME_REGISTRY.lock().unwrap();
        if let Some(handle) = registry.get(volume_name) {
            info!("Volume '{}' already open, reusing handle", volume_name);
            return Ok(handle.clone());
        }
    }

    // Determine socket path
    let socket_path = PathBuf::from(format!("/var/run/minions/volumes/{}.sock", volume_name));
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }

    // Open the volume
    let config = VolumeConfig::new(volume_name.to_string(), 0, s3_config)
        .with_socket_path(socket_path);

    let handle = Arc::new(VolumeHandle::open(config).await?);

    // Register it
    {
        let mut registry = VOLUME_REGISTRY.lock().unwrap();
        registry.insert(volume_name.to_string(), handle.clone());
    }

    info!("Volume '{}' opened successfully", volume_name);
    Ok(handle)
}

/// Close a volume and stop its NBD server
pub async fn close_volume(volume_name: &str) -> Result<()> {
    info!("Closing volume '{}'", volume_name);

    let handle = {
        let mut registry = VOLUME_REGISTRY.lock().unwrap();
        registry.remove(volume_name)
    };

    if let Some(handle) = handle {
        // Get the Arc'd handle and close it
        match Arc::try_unwrap(handle) {
            Ok(h) => h.close().await?,
            Err(arc) => {
                warn!("Volume '{}' still has {} references, leaving open", 
                      volume_name, Arc::strong_count(&arc));
            }
        }
    }

    Ok(())
}

/// Attach a volume to a VM
/// Returns the NBD device path (e.g., "/dev/nbd0")
pub async fn attach_volume_to_vm(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
) -> Result<String> {
    info!("Attaching volume '{}' to VM '{}'", volume_name, vm_name);

    let conn = db::open(db_path)?;

    // Get volume info
    let volume = db::get_volume(&conn, volume_name)?
        .with_context(|| format!("Volume '{}' not found", volume_name))?;

    if volume.status != "available" {
        anyhow::bail!("Volume '{}' is not available (status: {})", volume_name, volume.status);
    }

    // Get S3 config
    let s3_config = S3Config::from_env()
        .context("S3 configuration not set")?;

    // Open the volume (starts NBD server)
    let handle = open_volume(volume_name, s3_config).await?;

    // Connect nbd-client (blocking process call in blocking task)
    let socket_path = handle.socket_path().clone();
    let export_name = volume_name.to_string();
    let device_path = tokio::task::spawn_blocking(move || {
        storage::nbd_connect(&socket_path, &export_name)
    })
    .await
    .context("join error while connecting NBD client")?
    .context("Failed to connect NBD client")?;

    // Optional first-attach filesystem formatting
    if let Some(fs) = volume.fs_type.as_deref() {
        tokio::task::spawn_blocking({
            let device = device_path.clone();
            let fs = fs.to_string();
            move || storage::ensure_filesystem(&device, &fs)
        })
        .await
        .context("join error while ensuring filesystem")?
        .context("Failed to ensure filesystem on volume")?;
    }

    // Update database
    db::attach_volume(&conn, volume_name, vm_name, &device_path, "local")?;

    info!("Volume '{}' attached to VM '{}' as {}", volume_name, vm_name, device_path);
    Ok(device_path)
}

/// Detach a volume from a VM (full detach - clears database attachment)
pub async fn detach_volume_from_vm(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
) -> Result<()> {
    detach_volume_internal(db_path, vm_name, volume_name, true).await
}

/// Disconnect a volume from a VM (soft detach - keeps database attachment)
/// Used during VM stop to preserve volume configuration
async fn disconnect_volume_from_vm(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
) -> Result<()> {
    detach_volume_internal(db_path, vm_name, volume_name, false).await
}

/// Internal detach implementation
/// If `clear_db_attachment` is false, keeps the volume marked as attached in the database
async fn detach_volume_internal(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
    clear_db_attachment: bool,
) -> Result<()> {
    let action = if clear_db_attachment { "Detaching" } else { "Disconnecting" };
    info!("{} volume '{}' from VM '{}'", action, volume_name, vm_name);

    let conn = db::open(db_path)?;

    // Get volume info
    let volume = db::get_volume(&conn, volume_name)?
        .with_context(|| format!("Volume '{}' not found", volume_name))?;

    // Check if attached to this VM
    if volume.vm_name.as_deref() != Some(vm_name) {
        anyhow::bail!("Volume '{}' is not attached to VM '{}'", volume_name, vm_name);
    }

    // Disconnect NBD device if present
    if let Some(ref device) = volume.nbd_device {
        storage::nbd_disconnect(device)
            .context("Failed to disconnect NBD device")?;
    }

    // Close the volume (stops NBD server)
    close_volume(volume_name).await?;

    // Update database: either clear attachment or just clear the device path
    if clear_db_attachment {
        db::detach_volume(&conn, volume_name)?;
        info!("Volume '{}' detached from VM '{}'", volume_name, vm_name);
    } else {
        // Keep attachment but clear device path (since device is disconnected)
        db::update_volume_device(&conn, volume_name, None)?;
        info!("Volume '{}' disconnected from VM '{}' (attachment preserved)", volume_name, vm_name);
    }

    Ok(())
}

/// List all volumes attached to a VM
pub fn list_vm_volumes(db_path: &str, vm_name: &str) -> Result<Vec<db::Volume>> {
    let conn = db::open(db_path)?;
    db::list_volumes_by_vm(&conn, vm_name)
}

/// Reattach a volume during VM start (volume already marked as attached in DB)
async fn reattach_volume(db_path: &str, vm_name: &str, volume_name: &str) -> Result<String> {
    info!("Reattaching volume '{}' for VM '{}'", volume_name, vm_name);

    // Get S3 config
    let s3_config = S3Config::from_env()
        .context("S3 configuration not set")?;

    // Open the volume (starts NBD server)
    let handle = open_volume(volume_name, s3_config).await?;

    // Connect nbd-client (blocking process call in blocking task)
    let socket_path = handle.socket_path().clone();
    let export_name = volume_name.to_string();
    let device_path = tokio::task::spawn_blocking(move || {
        storage::nbd_connect(&socket_path, &export_name)
    })
    .await
    .context("join error while connecting NBD client")?
    .context("Failed to connect NBD client")?;

    // Update database with new device path
    let conn = db::open(db_path)?;
    db::attach_volume(&conn, volume_name, vm_name, &device_path, "local")?;

    info!("Volume '{}' reattached to VM '{}' as {}", volume_name, vm_name, device_path);
    Ok(device_path)
}

/// Attach all volumes for a VM (called during VM start)
/// This handles volumes that are already marked as attached in the database
pub async fn attach_all_vm_volumes(db_path: &str, vm_name: &str) -> Result<Vec<String>> {
    let volumes = list_vm_volumes(db_path, vm_name)?;
    
    if volumes.is_empty() {
        return Ok(Vec::new());
    }

    info!("Found {} volume(s) to attach for VM '{}'", volumes.len(), vm_name);
    let mut devices = Vec::new();

    for volume in volumes {
        match reattach_volume(db_path, vm_name, &volume.name).await {
            Ok(device) => {
                info!("  ✓ {} → {}", volume.name, device);
                devices.push(device);
            }
            Err(e) => {
                warn!("  ✗ {} failed: {}", volume.name, e);
                // Continue with other volumes
            }
        }
    }

    Ok(devices)
}

/// Disconnect all volumes for a VM (called during VM stop)
/// Disconnects NBD devices but preserves database attachments for automatic reattach on start
pub async fn disconnect_all_vm_volumes(db_path: &str, vm_name: &str) -> Result<()> {
    let volumes = list_vm_volumes(db_path, vm_name)?;

    if volumes.is_empty() {
        return Ok(());
    }

    info!("Disconnecting {} volume(s) from VM '{}'", volumes.len(), vm_name);

    for volume in volumes {
        if let Err(e) = disconnect_volume_from_vm(db_path, vm_name, &volume.name).await {
            warn!("Failed to disconnect volume '{}': {}", volume.name, e);
            // Continue with other volumes
        }
    }

    Ok(())
}

/// Detach all volumes for a VM (full detach - clears database attachments)
/// Used during VM destroy
pub async fn detach_all_vm_volumes(db_path: &str, vm_name: &str) -> Result<()> {
    let volumes = list_vm_volumes(db_path, vm_name)?;

    for volume in volumes {
        if let Err(e) = detach_volume_from_vm(db_path, vm_name, &volume.name).await {
            warn!("Failed to detach volume '{}': {}", volume.name, e);
            // Continue with other volumes
        }
    }

    Ok(())
}
