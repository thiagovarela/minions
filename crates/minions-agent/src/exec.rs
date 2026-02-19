use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::Command;
use tracing::{info, warn};

/// Maximum bytes to capture from stdout or stderr.
/// If output exceeds this, it will be truncated with a warning message.
const MAX_OUTPUT_BYTES: usize = 512 * 1024; // 512 KB

/// Execute a command and return (exit_code, stdout, stderr).
/// Output is capped at MAX_OUTPUT_BYTES per stream to prevent OOM.
pub async fn run(command: &str, args: &[String]) -> Result<(i32, String, String)> {
    info!("executing: {} {:?}", command, args);

    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn: {} {:?}", command, args))?;

    // Capture stdout and stderr with size limits
    let stdout_handle = child.stdout.take().expect("stdout was piped");
    let stderr_handle = child.stderr.take().expect("stderr was piped");

    let stdout_fut = read_limited(stdout_handle, MAX_OUTPUT_BYTES);
    let stderr_fut = read_limited(stderr_handle, MAX_OUTPUT_BYTES);

    // Wait for command and read output concurrently
    let (status, stdout_result, stderr_result) = tokio::join!(child.wait(), stdout_fut, stderr_fut);

    let exit_code = status
        .with_context(|| format!("failed to wait for {} {:?}", command, args))?
        .code()
        .unwrap_or(-1);

    let (stdout, stdout_truncated) = stdout_result?;
    let (stderr, stderr_truncated) = stderr_result?;

    if stdout_truncated || stderr_truncated {
        warn!(
            "command output truncated: stdout={}, stderr={}",
            stdout_truncated, stderr_truncated
        );
    }

    info!(
        "command finished: exit_code={}, stdout_len={}, stderr_len={}",
        exit_code,
        stdout.len(),
        stderr.len()
    );

    Ok((exit_code, stdout, stderr))
}

/// Read from an async reader up to `max_bytes`.
/// Returns (content, truncated).
async fn read_limited<R: AsyncReadExt + Unpin>(
    reader: R,
    max_bytes: usize,
) -> Result<(String, bool)> {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(max_bytes.min(8192));
    let mut total = 0usize;
    let mut truncated = false;

    loop {
        // Read into a temporary chunk
        let chunk_size = (max_bytes - total).min(8192);
        if chunk_size == 0 {
            // Reached the limit — discard remaining bytes
            truncated = true;
            let mut discard = vec![0u8; 8192];
            while reader.read(&mut discard).await? > 0 {}
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break; // EOF
        }

        buf.extend_from_slice(&chunk[..n]);
        total += n;
    }

    let mut content = String::from_utf8_lossy(&buf).to_string();
    if truncated {
        content.push_str("\n[... output truncated at 512KB limit ...]");
    }

    Ok((content, truncated))
}
