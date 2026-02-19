use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::info;

/// Write content to a file with specified permissions.
/// Creates parent directories if they don't exist.
pub fn write_file(path: &str, content: &str, mode: u32, append: bool) -> Result<()> {
    info!(
        "writing to {}: {} bytes, mode {:o}, append={}",
        path,
        content.len(),
        mode,
        append
    );

    let path_obj = Path::new(path);

    // Create parent directories if they don't exist
    if let Some(parent) = path_obj.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create parent dir {:?}", parent))?;

        // Set parent directory permissions (e.g., 0o700 for .ssh/)
        if path.contains("/.ssh/") {
            let parent_mode = if mode & 0o077 == 0 {
                0o700 // If file is owner-only, make parent owner-only too
            } else {
                0o755 // Otherwise, standard directory permissions
            };
            fs::set_permissions(parent, fs::Permissions::from_mode(parent_mode))
                .with_context(|| format!("set parent permissions {:?}", parent))?;
        }
    }

    // Write the file
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .with_context(|| format!("open {:?}", path))?;

    file.write_all(content.as_bytes())
        .with_context(|| format!("write to {:?}", path))?;

    // Flush to the virtio-blk device immediately so the data survives a
    // subsequent ACPI reboot (otherwise it may sit in the page cache).
    file.sync_all()
        .with_context(|| format!("sync {:?} to disk", path))?;

    // Set file permissions
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("set permissions {:o} on {:?}", mode, path))?;

    info!("wrote {} bytes to {}", content.len(), path);
    Ok(())
}
