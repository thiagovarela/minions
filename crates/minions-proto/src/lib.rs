//! Protocol types and frame codec for minions host↔guest communication.
//!
//! Messages are length-prefixed JSON frames:
//! - 4 bytes: message length (u32 big-endian)
//! - N bytes: JSON payload

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_SIZE: u32 = 1024 * 1024; // 1MB

/// Request from host to guest agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Health check / readiness probe.
    HealthCheck,

    /// Configure VM networking.
    ConfigureNetwork {
        ip: String,      // e.g. "10.0.0.2/16"
        gateway: String, // e.g. "10.0.0.1"
        dns: Vec<String>, // e.g. ["1.1.1.1", "8.8.8.8"]
    },

    /// Execute a command inside the VM.
    Exec {
        command: String,
        args: Vec<String>,
    },

    /// Report system status (uptime, memory, disk).
    ReportStatus,

    /// Write content to a file (for injecting SSH keys, etc.).
    /// Creates parent directories and sets appropriate permissions.
    WriteFile {
        path: String,
        content: String,
        mode: u32,      // Unix file permissions (e.g., 0o600)
        append: bool,   // If true, append; if false, overwrite
    },
}

/// Response from guest agent to host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    /// Success response.
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,

        #[serde(flatten)]
        data: Option<ResponseData>,
    },

    /// Error response.
    Error { message: String },
}

/// Additional data in responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseData {
    Health {
        uptime_secs: u64,
        hostname: String,
    },
    Exec {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    Status {
        uptime_secs: u64,
        memory_total_mb: u64,
        memory_used_mb: u64,
        disk_total_gb: u64,
        disk_used_gb: u64,
        /// CPU usage percentage across all cores (0.0–100.0).
        /// Measured over a ~100ms sample window.
        #[serde(default)]
        cpu_usage_percent: f64,
        /// Total bytes received on eth0 since boot.
        #[serde(default)]
        network_rx_bytes: u64,
        /// Total bytes transmitted on eth0 since boot.
        #[serde(default)]
        network_tx_bytes: u64,
        /// 1-minute load average.
        #[serde(default)]
        load_avg_1m: f64,
    },
}

impl Response {
    pub fn ok() -> Self {
        Response::Ok {
            message: None,
            data: None,
        }
    }

    pub fn ok_with_message(message: impl Into<String>) -> Self {
        Response::Ok {
            message: Some(message.into()),
            data: None,
        }
    }

    pub fn ok_with_data(data: ResponseData) -> Self {
        Response::Ok {
            message: None,
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }
}

/// Read a length-prefixed JSON frame from an async reader.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    // Read 4-byte length prefix
    let len = reader
        .read_u32()
        .await
        .context("failed to read frame length")?;

    if len > MAX_FRAME_SIZE {
        anyhow::bail!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE);
    }

    // Read JSON payload
    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .context("failed to read frame payload")?;

    serde_json::from_slice(&buf).context("failed to deserialize frame")
}

/// Write a length-prefixed JSON frame to an async writer.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(value).context("failed to serialize frame")?;
    let len = json.len() as u32;

    if len > MAX_FRAME_SIZE {
        anyhow::bail!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE);
    }

    // Write length prefix + payload
    writer
        .write_u32(len)
        .await
        .context("failed to write frame length")?;
    writer
        .write_all(&json)
        .await
        .context("failed to write frame payload")?;
    writer.flush().await.context("failed to flush frame")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let req = Request::HealthCheck;
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: Request = read_frame(&mut cursor).await.unwrap();

        matches!(decoded, Request::HealthCheck);
    }

    #[tokio::test]
    async fn test_response_serialization() {
        let resp = Response::ok_with_data(ResponseData::Health {
            uptime_secs: 42,
            hostname: "test".to_string(),
        });

        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();

        matches!(decoded, Response::Ok { .. });
    }
}
