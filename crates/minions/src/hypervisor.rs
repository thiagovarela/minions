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

/// Gracefully shut down a VM via the CH API, falling back to SIGKILL.
pub fn shutdown(name: &str, pid: Option<i64>) -> Result<()> {
    let api_socket = api_socket_path(name);

    if api_socket.exists() {
        // Try graceful power button press.
        let _ = curl_put(&api_socket.to_string_lossy(), "vm.power-button");
        std::thread::sleep(Duration::from_secs(5));

        // If still alive, force-shutdown VMM.
        if is_alive_pid(pid) {
            let _ = curl_put(&api_socket.to_string_lossy(), "vmm.shutdown");
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    // Last resort: SIGKILL.
    if is_alive_pid(pid) {
        force_kill(pid);
    }

    // Clean up socket files.
    let _ = std::fs::remove_file(&api_socket);
    let vsock_socket = vsock_socket_path(name);
    let _ = std::fs::remove_file(&vsock_socket);

    Ok(())
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

/// Check if a process is still alive.
pub fn is_alive_pid(pid: Option<i64>) -> bool {
    let Some(pid) = pid else { return false };
    if pid <= 0 {
        return false;
    }
    // kill -0 checks existence without sending a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Force-kill a process.
pub fn force_kill(pid: Option<i64>) {
    let Some(pid) = pid else { return };
    if pid > 0 {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}
