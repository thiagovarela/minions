use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tracing::info;

/// Execute a command and return (exit_code, stdout, stderr).
pub async fn run(command: &str, args: &[String]) -> Result<(i32, String, String)> {
    info!("executing: {} {:?}", command, args);

    let output = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| format!("failed to execute: {} {:?}", command, args))?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    info!(
        "command finished: exit_code={}, stdout_len={}, stderr_len={}",
        exit_code,
        stdout.len(),
        stderr.len()
    );

    Ok((exit_code, stdout, stderr))
}
