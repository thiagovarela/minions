//! Cloud-hypervisor process spawning and graceful shutdown.

use anyhow::{Context, Result};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const KERNEL_PATH: &str = "/var/lib/minions/kernel/vmlinux";
pub const RUN_DIR: &str = "/run/minions";

pub struct VmConfig {
    #[allow(dead_code)]
    pub name: String,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub mac: String,
    pub cid: u32,
    pub rootfs: PathBuf,
    pub tap: String,
    pub api_socket: PathBuf,
    pub vsock_socket: PathBuf,
    pub serial_log: PathBuf,
}

/// Ensure /run/minions/ exists.
pub fn ensure_run_dir() -> Result<()> {
    std::fs::create_dir_all(RUN_DIR).context("create /run/minions")?;
    Ok(())
}

pub fn api_socket_path(name: &str) -> PathBuf {
    PathBuf::from(RUN_DIR).join(format!("{name}.sock"))
}

pub fn vsock_socket_path(name: &str) -> PathBuf {
    PathBuf::from(RUN_DIR).join(format!("{name}.vsock"))
}

/// Spawn a cloud-hypervisor process detached from the parent.
/// Returns the child PID.
pub fn spawn(cfg: &VmConfig) -> Result<u32> {
    // Safety: setsid() is safe to call in a single-threaded child context.
    let mut cmd = Command::new("cloud-hypervisor");
    cmd.args([
        "--api-socket",
        cfg.api_socket.to_str().unwrap(),
        "--kernel",
        KERNEL_PATH,
        "--disk",
        &format!("path={}", cfg.rootfs.display()),
        "--cpus",
        &format!("boot={}", cfg.vcpus),
        "--memory",
        &format!("size={}M", cfg.memory_mb),
        "--net",
        &format!("tap={},mac={}", cfg.tap, cfg.mac),
        "--vsock",
        &format!("cid={},socket={}", cfg.cid, cfg.vsock_socket.display()),
        "--serial",
        &format!("file={}", cfg.serial_log.display()),
        "--console",
        "off",
        "--cmdline",
        "console=ttyS0 root=/dev/vda rw quiet",
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());

    // SAFETY: setsid() is async-signal-safe and returns -1 on error.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().context("spawn cloud-hypervisor")?;
    Ok(child.id())
}

/// Reboot a VM via the CH API (`vm.reboot`).
///
/// Takes the stored `api_socket` path from the DB record so it works correctly
/// even after a rename.  Cloud Hypervisor sends an ACPI reset to the guest;
/// the VMM process stays alive.
pub fn reboot(api_socket: &str) -> Result<()> {
    if !std::path::Path::new(api_socket).exists() {
        anyhow::bail!("CH API socket not found at '{api_socket}' — is the VM running?");
    }
    curl_put(api_socket, "vm.reboot").context("vm.reboot API call failed")?;
    Ok(())
}

/// Gracefully shut down a VM via the CH API, falling back to SIGKILL.
///
/// Uses the **stored** `api_socket` and `vsock_socket` paths from the DB
/// record so it works correctly even after a rename.
pub fn shutdown_vm(api_socket: &str, vsock_socket: &str, pid: Option<i64>) -> Result<()> {
    let api_path = std::path::Path::new(api_socket);

    if api_path.exists() {
        // Try graceful power button press.
        let _ = curl_put(api_socket, "vm.power-button");
        std::thread::sleep(Duration::from_secs(5));

        // If still alive, force-shutdown VMM.
        if is_alive_pid(pid) {
            let _ = curl_put(api_socket, "vmm.shutdown");
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    // Last resort: SIGKILL.
    if is_alive_pid(pid) {
        force_kill(pid);
    }

    // Clean up socket files.
    let _ = std::fs::remove_file(api_socket);
    let _ = std::fs::remove_file(vsock_socket);

    Ok(())
}

/// Convenience wrapper that derives socket paths from the VM name.
/// Only use this for cases where the VM has never been renamed.
pub fn shutdown(name: &str, pid: Option<i64>) -> Result<()> {
    let api_socket = api_socket_path(name);
    let vsock_socket = vsock_socket_path(name);
    shutdown_vm(
        &api_socket.to_string_lossy(),
        &vsock_socket.to_string_lossy(),
        pid,
    )
}

/// Send a PUT request to the CH API via the Unix socket using curl.
fn curl_put(socket: &str, endpoint: &str) -> Result<()> {
    let status = Command::new("curl")
        .args([
            "-s",
            "--unix-socket",
            socket,
            "-X",
            "PUT",
            &format!("http://localhost/api/v1/{endpoint}"),
        ])
        .status()
        .context("curl CH API")?;
    if !status.success() {
        anyhow::bail!("curl PUT {endpoint} failed");
    }
    Ok(())
}

/// Check if a process is still alive and appears to be cloud-hypervisor.
///
/// NOTE: This has a small PID reuse window. If the CH process dies and another
/// process reuses the PID before we check, we could get a false positive.
/// A more robust approach would store (PID, start_time) in the database and
/// verify both. For now, we check /proc/{pid}/comm to reduce false positives.
pub fn is_alive_pid(pid: Option<i64>) -> bool {
    let Some(pid) = pid else { return false };
    if pid <= 0 {
        return false;
    }

    // Check if process exists
    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
    if !alive {
        return false;
    }

    // Verify it looks like cloud-hypervisor
    is_likely_ch_process(pid)
}

/// Check if a PID appears to be a cloud-hypervisor process.
fn is_likely_ch_process(pid: i64) -> bool {
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
        let comm = comm.trim();
        // /proc/pid/comm is truncated to 15 chars, so "cloud-hypervisor" becomes "cloud-hypervi"
        comm.starts_with("cloud-hyper") || comm == "cloud-hypervisor"
    } else {
        // Can't read /proc entry — process might have died or we lack permissions.
        // Conservatively assume it's not a CH process.
        false
    }
}

/// Force-kill a process (with PID reuse mitigation).
pub fn force_kill(pid: Option<i64>) {
    let Some(pid) = pid else { return };
    if pid <= 0 {
        return;
    }

    // Safety check: verify it looks like cloud-hypervisor before SIGKILL
    if !is_likely_ch_process(pid) {
        tracing::warn!(
            "refusing to kill PID {} — not a cloud-hypervisor process (possible PID reuse)",
            pid
        );
        return;
    }

    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}
