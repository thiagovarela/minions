//! SSH proxy mode: bridge an incoming SSH session to a VM's sshd.
//!
//! When a user connects as `<vmname>@ssh.miniclankers.com`, we:
//! 1. Open a russh client connection to the VM's internal IP on port 22.
//! 2. Authenticate as `root` using the gateway's proxy key pair.
//! 3. Bridge channel data between the client and the VM using `ChannelStream`.

use std::sync::Arc;

use anyhow::{Context, Result};
use russh::client;
use russh::{ChannelId, Pty};
use russh_keys::key::{KeyPair, PublicKey};
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::server::ServerHandle;

// ── Minimal russh client Handler ──────────────────────────────────────────────

pub struct VmClientHandler;

#[async_trait::async_trait]
impl client::Handler for VmClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // Always trust VMs on the internal (trusted) network.
        Ok(true)
    }
}

// ── ConnectedVm ───────────────────────────────────────────────────────────────

/// An established SSH session to a VM.
pub struct ConnectedVm {
    pub channel: russh::Channel<client::Msg>,
}

impl ConnectedVm {
    /// Connect to `vm_ip:22` and authenticate as root with `proxy_key`.
    pub async fn connect(vm_ip: &str, proxy_key: Arc<KeyPair>) -> Result<Self> {
        let config = Arc::new(client::Config::default());
        let addr = format!("{}:22", vm_ip);

        let mut session = client::connect(config, addr.as_str(), VmClientHandler)
            .await
            .with_context(|| format!("connect to VM SSH at {}", addr))?;

        let authed = session
            .authenticate_publickey("root", proxy_key)
            .await
            .context("proxy key auth to VM")?;

        if !authed {
            anyhow::bail!(
                "gateway proxy key rejected by VM '{}'\n\
                 Hint: recreate the VM after running `minions serve --ssh-bind` \
                 at least once to generate the proxy key.",
                vm_ip
            );
        }

        let channel = session
            .channel_open_session()
            .await
            .context("open session channel on VM")?;

        // Drive the session in a background task; the channel keeps it alive.
        tokio::spawn(async move {
            if let Err(e) = session.await {
                debug!("VM client session ended: {}", e);
            }
        });

        Ok(ConnectedVm { channel })
    }

    /// Request a PTY on the VM channel.
    pub async fn request_pty(
        &mut self,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
    ) -> Result<()> {
        self.channel
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
            .context("pty_request to VM")
    }

    /// Request an interactive shell on the VM.
    pub async fn request_shell(&mut self) -> Result<()> {
        self.channel
            .request_shell(true)
            .await
            .context("shell_request to VM")
    }

    /// Execute a command on the VM.
    pub async fn exec(&mut self, command: &[u8]) -> Result<()> {
        self.channel.exec(true, command).await.context("exec on VM")
    }
}

// ── Bidirectional proxy ────────────────────────────────────────────────────────

/// Takes ownership of the VM channel, converts it to a stream, and:
/// * spawns a task that forwards VM stdout → client (via `client_handle`)
/// * returns the write half so the caller can forward client stdin → VM.
///
/// The returned writer implements `AsyncWrite + Send + Unpin`.
pub fn spawn_proxy(
    vm: ConnectedVm,
    client_handle: ServerHandle,
    client_channel_id: ChannelId,
) -> tokio::io::WriteHalf<russh::ChannelStream<client::Msg>> {
    let stream = vm.channel.into_stream();
    let (mut read_half, write_half) = tokio::io::split(stream);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 32_768];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = russh::CryptoVec::from(buf[..n].to_vec());
                    if client_handle.data(client_channel_id, data).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = client_handle.eof(client_channel_id).await;
        let _ = client_handle.close(client_channel_id).await;
    });

    write_half
}
