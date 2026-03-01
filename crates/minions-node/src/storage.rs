//! Rootfs management: copy base image per VM, clean up on destroy.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub const IMAGES_DIR: &str = "/var/lib/minions/images";
pub const VMS_DIR: &str = "/var/lib/minions/vms";
pub const SNAPSHOTS_DIR: &str = "/var/lib/minions/snapshots";

/// Supported operating systems for VM images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OsType {
    #[default]
    Ubuntu,
    Fedora,
    NixOS,
}

impl OsType {
    /// Parse OS type from string (case-insensitive).
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ubuntu" => Ok(OsType::Ubuntu),
            "fedora" => Ok(OsType::Fedora),
            "nixos" => Ok(OsType::NixOS),
            _ => anyhow::bail!(
                "unsupported OS '{}' (available: ubuntu, fedora, nixos)",
                s
            ),
        }
    }

    /// Get the base image filename for this OS.
    pub fn image_name(&self) -> &'static str {
        match self {
            OsType::Ubuntu => "base-ubuntu.ext4",
            OsType::Fedora => "base-fedora.ext4",
            OsType::NixOS => "base-nixos.ext4",
        }
    }

    /// Get the full path to the base image for this OS.
    pub fn base_image_path(&self) -> PathBuf {
        PathBuf::from(IMAGES_DIR).join(self.image_name())
    }

    /// Get the path to the vmlinux kernel for this OS.
    ///
    /// Ubuntu and Fedora share the Cloud Hypervisor project kernel.
    /// NixOS uses its own kernel extracted from the NixOS build.
    pub fn kernel_path(&self) -> PathBuf {
        match self {
            OsType::Ubuntu | OsType::Fedora => {
                PathBuf::from("/var/lib/minions/kernel/vmlinux")
            }
            OsType::NixOS => PathBuf::from("/var/lib/minions/kernel/vmlinux-nixos"),
        }
    }

    /// Optional initramfs path for this OS.
    ///
    /// Ubuntu/Fedora images currently boot without an initramfs.
    /// NixOS uses an initramfs generated alongside the kernel.
    pub fn initramfs_path(&self) -> Option<PathBuf> {
        match self {
            OsType::Ubuntu | OsType::Fedora => None,
            OsType::NixOS => Some(PathBuf::from("/var/lib/minions/kernel/initrd-nixos")),
        }
    }

    /// String representation for storage/display.
    pub fn as_str(&self) -> &'static str {
        match self {
            OsType::Ubuntu => "ubuntu",
            OsType::Fedora => "fedora",
            OsType::NixOS => "nixos",
        }
    }
}

impl std::fmt::Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Return the rootfs path for a given VM name.
#[allow(dead_code)]
pub fn rootfs_path(name: &str) -> PathBuf {
    PathBuf::from(VMS_DIR).join(name).join("rootfs.ext4")
}

/// List available OS images that have been built.
pub fn list_available_os() -> Vec<OsType> {
    let mut available = Vec::new();
    for os in [OsType::Ubuntu, OsType::Fedora, OsType::NixOS] {
        if os.base_image_path().exists() {
            available.push(os);
        }
    }
    available
}

/// Copy the base image to a per-VM rootfs.
/// The base image must already contain the minions-agent binary + systemd unit.
pub fn create_rootfs(name: &str) -> Result<PathBuf> {
    create_rootfs_with_os(name, OsType::default())
}

/// Copy the base image for a specific OS to a per-VM rootfs.
/// The base image must already contain the minions-agent binary + systemd unit.
pub fn create_rootfs_with_os(name: &str, os: OsType) -> Result<PathBuf> {
    let vm_dir = PathBuf::from(VMS_DIR).join(name);
    std::fs::create_dir_all(&vm_dir).with_context(|| format!("create VM dir {:?}", vm_dir))?;

    let dst = vm_dir.join("rootfs.ext4");
    let base = os.base_image_path();

    if !base.exists() {
        let available = list_available_os();
        if available.is_empty() {
            anyhow::bail!(
                "no base images found at {IMAGES_DIR}\n\
                 Build one first: sudo ./scripts/build-base-image.sh --os {os}\n\
                 Then bake the agent: sudo ./scripts/bake-agent.sh --os {os}"
            );
        } else {
            let available_str: Vec<_> = available.iter().map(|o| o.as_str()).collect();
            anyhow::bail!(
                "base image for '{os}' not found at {}\n\
                 Available images: {}\n\
                 Build it first: sudo ./scripts/build-base-image.sh --os {os}\n\
                 Then bake the agent: sudo ./scripts/bake-agent.sh --os {os}",
                base.display(),
                available_str.join(", ")
            );
        }
    }

    // Use `cp --sparse=always` for a fast copy that preserves sparse blocks.
    let status = std::process::Command::new("cp")
        .args([
            "--sparse=always",
            base.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
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
    std::fs::create_dir_all(&vm_dir).with_context(|| format!("create VM dir {:?}", vm_dir))?;

    let dst = vm_dir.join("rootfs.ext4");

    let status = std::process::Command::new("cp")
        .args([
            "--sparse=always",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ])
        .status()
        .context("spawn cp")?;

    if !status.success() {
        anyhow::bail!(
            "cp rootfs from '{}' to '{}' failed",
            src.display(),
            dst.display()
        );
    }

    Ok(dst)
}

/// Remove the per-VM directory and all its contents.
pub fn destroy_rootfs(name: &str) -> Result<()> {
    let vm_dir = PathBuf::from(VMS_DIR).join(name);
    if vm_dir.exists() {
        std::fs::remove_dir_all(&vm_dir).with_context(|| format!("remove {:?}", vm_dir))?;
    }
    Ok(())
}

/// Resize an ext4 rootfs image (grow only).
///
/// The VM **must be stopped** before calling this. This function:
/// 1. Validates new_size_gb is >= current size
/// 2. Extends the file using `truncate`
/// 3. Checks filesystem integrity using `e2fsck -f -y`
/// 4. Grows the ext4 filesystem using `resize2fs`
///
/// Only growing is supported (ext4 cannot be shrunk online).
pub fn resize_rootfs(rootfs_path: &str, new_size_gb: u32) -> Result<()> {
    let path = Path::new(rootfs_path);
    if !path.exists() {
        anyhow::bail!("rootfs not found at '{}'", rootfs_path);
    }

    // Get current size in bytes
    let current_bytes = std::fs::metadata(path)
        .context("read rootfs metadata")?
        .len();
    let current_gb = (current_bytes as f64 / (1024.0 * 1024.0 * 1024.0)).ceil() as u32;

    // Validate: can only grow, not shrink
    if new_size_gb < current_gb {
        anyhow::bail!(
            "cannot shrink disk from {}GB to {}GB (ext4 only supports growing)",
            current_gb,
            new_size_gb
        );
    }

    if new_size_gb == current_gb {
        // Already at target size, no-op
        return Ok(());
    }

    // Step 1: Extend the file using truncate
    let status = std::process::Command::new("truncate")
        .args(["--size", &format!("{}G", new_size_gb), rootfs_path])
        .status()
        .context("spawn truncate")?;

    if !status.success() {
        anyhow::bail!("truncate failed for '{}'", rootfs_path);
    }

    // Step 2: Check filesystem integrity before resizing
    // resize2fs requires this check to be run first
    let status = std::process::Command::new("e2fsck")
        .args(["-f", "-y", rootfs_path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("spawn e2fsck")?;

    // e2fsck returns 0 (no errors) or 1 (errors corrected) on success
    let exit_code = status.code().unwrap_or(255);
    if exit_code > 1 {
        anyhow::bail!(
            "e2fsck failed for '{}' with exit code {} — filesystem may be corrupted",
            rootfs_path,
            exit_code
        );
    }

    // Step 3: Grow the ext4 filesystem
    let status = std::process::Command::new("resize2fs")
        .arg(rootfs_path)
        .status()
        .context("spawn resize2fs")?;

    if !status.success() {
        anyhow::bail!(
            "resize2fs failed for '{}' — file extended to {}GB but filesystem not grown",
            rootfs_path,
            new_size_gb
        );
    }

    Ok(())
}

/// Path to the serial log for a VM.
pub fn serial_log_path(name: &str) -> PathBuf {
    PathBuf::from(VMS_DIR).join(name).join("serial.log")
}

// ── Snapshot storage ──────────────────────────────────────────────────────────

/// Directory for a specific VM snapshot.
/// Layout: /var/lib/minions/snapshots/{vm_name}/{snap_name}/
pub fn snapshot_dir(vm_name: &str, snap_name: &str) -> PathBuf {
    PathBuf::from(SNAPSHOTS_DIR).join(vm_name).join(snap_name)
}

/// Rootfs path within a snapshot directory.
pub fn snapshot_rootfs_path(vm_name: &str, snap_name: &str) -> PathBuf {
    snapshot_dir(vm_name, snap_name).join("rootfs.ext4")
}

/// Copy a VM's rootfs into a snapshot directory using `cp --sparse=always`.
///
/// Returns `(snapshot_rootfs_path, size_bytes)`.
/// The source `vm_rootfs_path` is the stored path from the DB record.
pub fn create_snapshot(
    vm_rootfs_path: &str,
    vm_name: &str,
    snap_name: &str,
) -> Result<(PathBuf, u64)> {
    let src = Path::new(vm_rootfs_path);
    if !src.exists() {
        anyhow::bail!(
            "VM rootfs not found at '{}' — cannot create snapshot",
            src.display()
        );
    }

    let dir = snapshot_dir(vm_name, snap_name);
    std::fs::create_dir_all(&dir).with_context(|| format!("create snapshot dir {:?}", dir))?;

    let dst = dir.join("rootfs.ext4");

    let status = std::process::Command::new("cp")
        .args(["--sparse=always", vm_rootfs_path, dst.to_str().unwrap()])
        .status()
        .context("spawn cp for snapshot")?;

    if !status.success() {
        anyhow::bail!(
            "cp failed when creating snapshot '{}' for VM '{}'",
            snap_name,
            vm_name
        );
    }

    let size_bytes = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);

    Ok((dst, size_bytes))
}

/// Restore a snapshot by overwriting the VM's rootfs with the snapshot copy.
///
/// The VM **must be stopped** before calling this. The caller is responsible
/// for enforcing that.
pub fn restore_snapshot(vm_rootfs_path: &str, vm_name: &str, snap_name: &str) -> Result<()> {
    let snap_rootfs = snapshot_rootfs_path(vm_name, snap_name);
    if !snap_rootfs.exists() {
        anyhow::bail!(
            "snapshot rootfs not found at '{}' — was it deleted?",
            snap_rootfs.display()
        );
    }

    let status = std::process::Command::new("cp")
        .args([
            "--sparse=always",
            snap_rootfs.to_str().unwrap(),
            vm_rootfs_path,
        ])
        .status()
        .context("spawn cp for snapshot restore")?;

    if !status.success() {
        anyhow::bail!(
            "cp failed when restoring snapshot '{}' for VM '{}'",
            snap_name,
            vm_name
        );
    }

    Ok(())
}

/// Delete the files for a specific snapshot.
pub fn delete_snapshot_files(vm_name: &str, snap_name: &str) -> Result<()> {
    let dir = snapshot_dir(vm_name, snap_name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).with_context(|| format!("remove snapshot dir {:?}", dir))?;
    }
    Ok(())
}

/// Delete all snapshot files for a VM (called when the VM is destroyed).
pub fn delete_all_snapshot_files(vm_name: &str) -> Result<()> {
    let vm_snap_dir = PathBuf::from(SNAPSHOTS_DIR).join(vm_name);
    if vm_snap_dir.exists() {
        std::fs::remove_dir_all(&vm_snap_dir)
            .with_context(|| format!("remove all snapshots for VM '{}'", vm_name))?;
    }
    Ok(())
}
