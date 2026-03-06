//! Volume management operations

use anyhow::{Context, Result};
use minions_db as db;
use rusqlite::Connection;
use uuid::Uuid;

/// Create a new volume
pub async fn create(
    db_path: &str,
    name: &str,
    size_gb: u64,
) -> Result<db::Volume> {
    // Validate S3 configuration
    let s3_config = minions_volume::s3::S3Config::from_env()
        .context("S3 configuration not set (check MINIONS_S3_* environment variables)")?;

    let size_bytes = size_gb * 1024 * 1024 * 1024;

    // Create volume in S3
    let volume_config = minions_volume::VolumeConfig::new(
        name.to_string(),
        size_bytes,
        s3_config.clone(),
    );

    minions_volume::VolumeHandle::create(volume_config)
        .await
        .context("Failed to create volume in S3")?;

    // Add to database
    let conn = db::open(db_path)?;
    let volume = db::Volume {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        size_bytes: size_bytes as i64,
        status: "available".to_string(),
        vm_name: None,
        nbd_device: None,
        s3_bucket: s3_config.bucket.clone(),
        s3_prefix: format!("volumes/{}", name),
        host_id: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    db::insert_volume(&conn, &volume)?;

    Ok(volume)
}

/// List all volumes
pub fn list(conn: &Connection) -> Result<Vec<db::Volume>> {
    db::list_volumes(conn)
}

/// Get a volume by name
pub fn get(conn: &Connection, name: &str) -> Result<Option<db::Volume>> {
    db::get_volume(conn, name)
}

/// Attach a volume to a VM
pub async fn attach(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
) -> Result<db::Volume> {
    // Use the minions-node volume module for actual attachment
    let _device_path = minions_node::volume::attach_volume_to_vm(db_path, vm_name, volume_name).await?;

    let conn = db::open(db_path)?;
    db::get_volume(&conn, volume_name)?
        .with_context(|| format!("Failed to retrieve updated volume"))
}

/// Detach a volume from a VM
pub async fn detach(
    db_path: &str,
    vm_name: &str,
    volume_name: &str,
) -> Result<db::Volume> {
    // Use the minions-node volume module for actual detachment
    minions_node::volume::detach_volume_from_vm(db_path, vm_name, volume_name).await?;

    let conn = db::open(db_path)?;
    db::get_volume(&conn, volume_name)?
        .with_context(|| format!("Failed to retrieve updated volume"))
}

/// Destroy a volume
pub async fn destroy(
    db_path: &str,
    name: &str,
) -> Result<()> {
    let conn = db::open(db_path)?;

    // Get volume
    let volume = db::get_volume(&conn, name)?
        .with_context(|| format!("Volume '{}' not found", name))?;

    // Check if volume is attached
    if volume.vm_name.is_some() {
        anyhow::bail!("Volume '{}' is attached to VM '{}'. Detach it first.", 
                     name, volume.vm_name.unwrap());
    }

    // Delete from S3
    let s3_config = minions_volume::s3::S3Config::from_env()
        .context("S3 configuration not set")?;

    minions_volume::VolumeHandle::destroy(name, s3_config)
        .await
        .context("Failed to delete volume from S3")?;

    // Delete from database
    db::delete_volume(&conn, name)?;

    Ok(())
}
