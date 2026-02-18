//! VSOCK client: connect, handshake, send requests.

use anyhow::{Context, Result};
use minions_proto::{read_frame, write_frame, Request, Response};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::sleep;

/// Connect to the VSOCK proxy socket and perform the CONNECT handshake.
pub async fn connect(vsock_socket: &Path) -> Result<UnixStream> {
    let mut stream = UnixStream::connect(vsock_socket)
        .await
        .with_context(|| format!("connect to {:?}", vsock_socket))?;

    stream
        .write_all(b"CONNECT 1024\n")
        .await
        .context("send CONNECT handshake")?;

    // Consume stream into BufReader so into_inner() returns ownership.
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read OK from agent")?;

    if !line.starts_with("OK ") {
        anyhow::bail!("VSOCK handshake failed: {}", line.trim());
    }

    Ok(reader.into_inner())
}

/// Send a single request and read the response.
pub async fn send_request(vsock_socket: &Path, request: Request) -> Result<Response> {
    let mut stream = connect(vsock_socket).await?;
    write_frame(&mut stream, &request)
        .await
        .context("write request frame")?;
    let response: Response = read_frame(&mut stream)
        .await
        .context("read response frame")?;
    Ok(response)
}

/// Wait until the agent responds to a health check, up to `timeout`.
pub async fn wait_ready(vsock_socket: &Path, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut backoff = Duration::from_millis(100);

    loop {
        if send_request(vsock_socket, Request::HealthCheck).await.is_ok() {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "agent at {:?} did not become ready within {:?}",
                vsock_socket,
                timeout
            );
        }

        sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(2));
    }
}

/// Configure guest networking via the agent.
pub async fn configure_network(
    vsock_socket: &Path,
    ip: &str,
    gateway: &str,
    dns: Vec<String>,
) -> Result<()> {
    let response = send_request(
        vsock_socket,
        Request::ConfigureNetwork {
            ip: ip.to_string(),
            gateway: gateway.to_string(),
            dns,
        },
    )
    .await?;

    match response {
        Response::Ok { .. } => Ok(()),
        Response::Error { message } => anyhow::bail!("agent error: {message}"),
    }
}
