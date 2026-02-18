//! Rootfs management: copy base image per VM, clean up on destroy.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub const BASE_IMAGE: &str = "/var/lib/minions/images/base-ubuntu.ext4";
pub const VMS_DIR: &str = "/var/lib/minions/vms";

/// Return the rootfs path for a given VM name.
#[allow(dead_code)]
pub fn rootfs_path(name: &str) -> PathBuf {
    PathBuf::from(VMS_DIR).join(name).join("rootfs.ext4")
}

/// Copy the base image to a per-VM rootfs.
/// The base image must already contain the minions-agent binary + systemd unit.
pub fn create_rootfs(name: &str) -> Result<PathBuf> {
    let vm_dir = PathBuf::from(VMS_DIR).join(name);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("create VM dir {:?}", vm_dir))?;

    let dst = vm_dir.join("rootfs.ext4");
    let base = Path::new(BASE_IMAGE);

    if !base.exists() {
        anyhow::bail!(
            "base image not found at {BASE_IMAGE}\n\
             Build it first with the Phase 1/2 setup scripts."
        );
    }

    // Use `cp --sparse=always` for a fast copy that preserves sparse blocks.
    let status = std::process::Command::new("cp")
        .args(["--sparse=always", BASE_IMAGE, dst.to_str().unwrap()])
        .status()
        .context("spawn cp")?;

    if !status.success() {
        anyhow::bail!("cp base image failed");
    }

    Ok(dst)
}

/// Copy an existing VM's rootfs to a new VM directory.
///
/// `source_rootfs` is the **stored** rootfs path from the DB record, so this
/// works correctly even when the source VM was renamed while running (in which
/// case the filesystem path does not match the VM name).
///
/// Uses `cp --sparse=always` for a fast, sparse-preserving copy.
pub fn copy_rootfs(source_rootfs: &str, dest_name: &str) -> Result<PathBuf> {
    let src = std::path::PathBuf::from(source_rootfs);
    if !src.exists() {
        anyhow::bail!(
            "source rootfs not found at {} — is the source VM valid?",
            src.display()
        );
    }

    let vm_dir = PathBuf::from(VMS_DIR).join(dest_name);
    std::fs::create_dir_all(&vm_dir)
        .with_context(|| format!("create VM dir {:?}", vm_dir))?;

    let dst = vm_dir.join("rootfs.ext4");

    let status = std::process::Command::new("cp")
        .args(["--sparse=always", src.to_str().unwrap(), dst.to_str().unwrap()])
        .status()
        .context("spawn cp")?;

    if !status.success() {
        anyhow::bail!("cp rootfs from '{}' to '{}' failed", src.display(), dst.display());
    }

    Ok(dst)
}

/// Remove the per-VM directory and all its contents.
pub fn destroy_rootfs(name: &str) -> Result<()> {
    let vm_dir = PathBuf::from(VMS_DIR).join(name);
    if vm_dir.exists() {
        std::fs::remove_dir_all(&vm_dir)
            .with_context(|| format!("remove {:?}", vm_dir))?;
    }
    Ok(())
}

/// Path to the serial log for a VM.
pub fn serial_log_path(name: &str) -> PathBuf {
    PathBuf::from(VMS_DIR).join(name).join("serial.log")
}
