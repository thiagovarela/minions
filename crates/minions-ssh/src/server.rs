//! russh Server + Handler implementation for the SSH gateway.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, Pty};
use russh_keys::PublicKeyBase64;
use russh_keys::key::PublicKey;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use crate::commands::ApiClient;
use crate::db::User;
use crate::proxy::{ConnectedVm, spawn_proxy};

/// The server::Handle type (used to write back to the SSH client from async tasks).
pub type ServerHandle = russh::server::Handle;

// ── Session mode ──────────────────────────────────────────────────────────────

enum SessionMode {
    /// Not yet determined (between auth and first channel request).
    Pending,
    /// Collecting the user's email for first-time registration.
    Registration {
        after: AfterRegistration,
        email_buf: String,
    },
    /// Registered user in interactive command mode.
    Command { line_buf: String },
    /// Proxy mode: stdin bytes go to the VM via this writer.
    Proxy {
        vm_stdin: tokio::io::WriteHalf<russh::ChannelStream<russh::client::Msg>>,
    },
}

#[derive(Clone)]
enum AfterRegistration {
    Command,
    Proxy { vm_name: String },
}

// ── PTY params (stored during pty_request, forwarded on shell/exec) ───────────

#[derive(Default, Clone)]
struct PtyParams {
    term: String,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    modes: Vec<(Pty, u32)>,
}

// ── Connection handler ────────────────────────────────────────────────────────

pub struct ConnectionHandler {
    config: Arc<crate::GatewayConfig>,
    peer_addr: Option<SocketAddr>,

    /// SSH username the client used (e.g. "minions" or a VM name).
    ssh_username: String,
    /// The public key presented during auth.
    pending_key: Option<PublicKey>,
    /// Set when the key matches a registered user.
    authed_user: Option<User>,

    /// Set in channel_open_session.
    client_handle: Option<ServerHandle>,
    client_channel_id: Option<ChannelId>,

    /// Stored between pty_request and shell/exec_request.
    pty: Option<PtyParams>,

    /// Current session state.
    mode: SessionMode,
}

impl ConnectionHandler {
    pub fn new(config: Arc<crate::GatewayConfig>, peer_addr: Option<SocketAddr>) -> Self {
        Self {
            config,
            peer_addr,
            ssh_username: String::new(),
            pending_key: None,
            authed_user: None,
            client_handle: None,
            client_channel_id: None,
            pty: None,
            mode: SessionMode::Pending,
        }
    }

    fn api(&self) -> ApiClient {
        ApiClient::new(
            self.config.api_base_url.clone(),
            self.config.api_key.clone(),
        )
    }

    fn fingerprint(key: &PublicKey) -> String {
        key.fingerprint()
    }

    fn key_to_str(key: &PublicKey) -> String {
        format!("{} {}", key.name(), key.public_key_base64())
    }

    async fn send(&self, bytes: impl Into<Vec<u8>>) {
        if let (Some(h), Some(id)) = (&self.client_handle, self.client_channel_id) {
            let _ = h.data(id, CryptoVec::from(bytes.into())).await;
        }
    }

    async fn close_err(&self, msg: &str) {
        self.send(format!("error: {}\r\n", msg)).await;
        if let (Some(h), Some(id)) = (&self.client_handle, self.client_channel_id) {
            let _ = h.exit_status_request(id, 1).await;
            let _ = h.eof(id).await;
            let _ = h.close(id).await;
        }
    }

    /// Look up a VM by name via the API, verify ownership, and return its IP.
    ///
    /// Ownership is checked when the user is a registered SSH gateway user.
    /// An unregistered user connecting in proxy mode is caught earlier during
    /// shell/exec handling (they get the registration prompt).
    async fn resolve_vm(&self, vm_name: &str) -> Result<String> {
        let api = self.api();
        let vm = api
            .get_vm(vm_name)
            .await?
            .ok_or_else(|| anyhow::anyhow!("VM '{}' not found", vm_name))?;

        // Enforce ownership: the VM must belong to the authenticated user.
        // We use a deliberately vague error to avoid leaking VM existence.
        if let Some(ref user) = self.authed_user {
            match &vm.owner_id {
                Some(oid) if oid == &user.id => {} // ✓ owned by this user
                _ => anyhow::bail!("VM '{}' not found", vm_name),
            }
        }

        if vm.status != "running" {
            anyhow::bail!(
                "VM '{}' is {} — it must be running to SSH into it",
                vm_name,
                vm.status
            );
        }
        Ok(vm.ip)
    }

    /// Connect to a VM and set up the bidirectional proxy.
    /// Sends the shell or exec request on the VM channel.
    async fn start_proxy_shell(&mut self, vm_name: &str) -> Result<()> {
        let vm_ip = self.resolve_vm(vm_name).await?;
        let mut vm = ConnectedVm::connect(&vm_ip, Arc::clone(&self.config.proxy_key)).await?;

        // Forward PTY if the client requested one.
        if let Some(ref pty) = self.pty.clone() {
            vm.request_pty(
                &pty.term,
                pty.col_width,
                pty.row_height,
                pty.pix_width,
                pty.pix_height,
                &pty.modes,
            )
            .await?;
        }

        vm.request_shell().await?;

        let handle = self.client_handle.clone().expect("handle set");
        let cid = self.client_channel_id.expect("cid set");
        let vm_stdin = spawn_proxy(vm, handle, cid);
        self.mode = SessionMode::Proxy { vm_stdin };
        Ok(())
    }

    async fn start_proxy_exec(&mut self, vm_name: &str, command: &[u8]) -> Result<()> {
        let vm_ip = self.resolve_vm(vm_name).await?;
        let mut vm = ConnectedVm::connect(&vm_ip, Arc::clone(&self.config.proxy_key)).await?;
        vm.exec(command).await?;

        let handle = self.client_handle.clone().expect("handle set");
        let cid = self.client_channel_id.expect("cid set");
        let vm_stdin = spawn_proxy(vm, handle, cid);
        self.mode = SessionMode::Proxy { vm_stdin };
        Ok(())
    }

    async fn complete_registration(
        &mut self,
        email: String,
        after: AfterRegistration,
        session: &mut Session,
        channel: ChannelId,
    ) -> Result<()> {
        session.data(channel, CryptoVec::from(b"\r\n".to_vec()));

        if !email.contains('@') || email.len() < 5 {
            session.data(
                channel,
                CryptoVec::from(b"Invalid email. Try again: ".to_vec()),
            );
            if let SessionMode::Registration { email_buf, .. } = &mut self.mode {
                email_buf.clear();
            }
            return Ok(());
        }

        let key = self.pending_key.clone().expect("pending key set");
        let fp = Self::fingerprint(&key);
        let key_str = Self::key_to_str(&key);

        let conn = crate::db::open(&self.config.db_path)?;
        match crate::db::create_user(&conn, &email, &key_str, &fp) {
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") {
                    session.data(
                        channel,
                        CryptoVec::from(
                            "Email already registered — use the key that belongs to that account.\r\n"
                                .as_bytes()
                                .to_vec(),
                        ),
                    );
                } else {
                    session.data(
                        channel,
                        CryptoVec::from(format!("Registration error: {}\r\n", msg).into_bytes()),
                    );
                }
                return Ok(());
            }
            Ok(user) => {
                self.authed_user = Some(user.clone());
                info!(email = %user.email, peer = ?self.peer_addr, "new user registered");
                session.data(
                    channel,
                    CryptoVec::from(
                        format!("✓ Registered! Welcome, {}.\r\n\r\n", user.email).into_bytes(),
                    ),
                );
            }
        }

        match after {
            AfterRegistration::Command => {
                self.mode = SessionMode::Command {
                    line_buf: String::new(),
                };
                session.data(
                    channel,
                    CryptoVec::from(b"Type 'help' for available commands.\r\n\r\n$ ".to_vec()),
                );
            }
            AfterRegistration::Proxy { vm_name } => match self.start_proxy_shell(&vm_name).await {
                Ok(()) => {}
                Err(e) => {
                    session.data(
                        channel,
                        CryptoVec::from(format!("error: {}\r\n", e).into_bytes()),
                    );
                }
            },
        }
        Ok(())
    }
}

// ── russh Handler impl ────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Handler for ConnectionHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.ssh_username = user.to_string();
        self.pending_key = Some(public_key.clone());

        let fp = Self::fingerprint(public_key);
        let conn = crate::db::open(&self.config.db_path)?;
        self.authed_user = crate::db::get_user_by_fingerprint(&conn, &fp)?;

        if let Some(ref u) = self.authed_user {
            info!(peer = ?self.peer_addr, email = %u.email, "authenticated");
        } else {
            info!(peer = ?self.peer_addr, ssh_user = %user, "unknown key — will prompt for registration");
        }

        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.client_handle = Some(session.handle());
        self.client_channel_id = Some(channel.id());
        debug!(peer = ?self.peer_addr, channel = ?channel.id(), "session opened");
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel);
        self.pty = Some(PtyParams {
            term: term.to_string(),
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes: modes.to_vec(),
        });
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel);

        let is_proxy = self.ssh_username != self.config.command_user;

        // Unregistered user → prompt for email.
        if self.authed_user.is_none() {
            let after = if is_proxy {
                AfterRegistration::Proxy {
                    vm_name: self.ssh_username.clone(),
                }
            } else {
                AfterRegistration::Command
            };
            self.mode = SessionMode::Registration {
                after,
                email_buf: String::new(),
            };
            session.data(
                channel,
                CryptoVec::from(
                    b"Welcome to MINICLANKERS.COM\r\n\r\nEnter your email to register: ".to_vec(),
                ),
            );
            return Ok(());
        }

        let user = self.authed_user.clone().unwrap();

        if is_proxy {
            let vm_name = self.ssh_username.clone();
            match self.start_proxy_shell(&vm_name).await {
                Ok(()) => {}
                Err(e) => self.close_err(&e.to_string()).await,
            }
        } else {
            // Command mode: interactive shell.
            self.mode = SessionMode::Command {
                line_buf: String::new(),
            };
            let banner = format!(
                "MINICLANKERS.COM — logged in as {}\r\nType 'help' for commands.\r\n\r\n$ ",
                user.email
            );
            session.data(channel, CryptoVec::from(banner.into_bytes()));
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel);
        let cmd_str = String::from_utf8_lossy(data).to_string();

        // Unregistered user — must register interactively first.
        if self.authed_user.is_none() {
            let msg = "Register first: ssh minions@ssh.miniclankers.com\r\n";
            let _ = session.data(channel, CryptoVec::from(msg.as_bytes().to_vec()));
            session.exit_status_request(channel, 1);
            session.eof(channel);
            session.close(channel);
            return Ok(());
        }

        let user = self.authed_user.clone().unwrap();
        let is_proxy = self.ssh_username != self.config.command_user;

        if is_proxy {
            let vm_name = self.ssh_username.clone();
            match self.start_proxy_exec(&vm_name, data).await {
                Ok(()) => {}
                Err(e) => self.close_err(&e.to_string()).await,
            }
            return Ok(());
        }

        // Command mode exec: run command, return output, exit.
        let api = self.api();
        let db_path = self.config.db_path.clone();
        let (output, code) = crate::commands::run(&cmd_str, &user, &api, &db_path).await;
        session.data(channel, CryptoVec::from(output.into_bytes()));
        session.exit_status_request(channel, code);
        session.eof(channel);
        session.close(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // ── Registration: collect email ───────────────────────────────────────
        // Inner block releases the mutable borrow before calling complete_registration.
        let reg_action: Option<(String, AfterRegistration)> = {
            if let SessionMode::Registration { email_buf, after } = &mut self.mode {
                let mut action = None;
                for &b in data {
                    match b {
                        b'\r' | b'\n' => {
                            let email = email_buf.trim().to_lowercase();
                            action = Some((email, after.clone()));
                            break;
                        }
                        0x7f | 0x08 => {
                            if !email_buf.is_empty() {
                                email_buf.pop();
                                session.data(channel, CryptoVec::from(b"\x08 \x08".to_vec()));
                            }
                        }
                        c => {
                            email_buf.push(c as char);
                            session.data(channel, CryptoVec::from(vec![c]));
                        }
                    }
                }
                action
            } else {
                None
            }
        }; // ← mutable borrow released here
        if let Some((email, after)) = reg_action {
            self.complete_registration(email, after, session, channel)
                .await?;
            return Ok(());
        }
        if matches!(self.mode, SessionMode::Registration { .. }) {
            return Ok(()); // still collecting input, no newline yet
        }

        // ── Proxy: forward stdin to VM ────────────────────────────────────────
        if let SessionMode::Proxy { vm_stdin } = &mut self.mode {
            if let Err(e) = vm_stdin.write_all(data).await {
                debug!("proxy stdin write error: {}", e);
            }
            return Ok(()); // borrow of vm_stdin ends here, before any &self call
        }

        // ── Command: line-buffered shell ──────────────────────────────────────
        // Use an inner block so the mutable borrow of self.mode is released
        // before we call self.api() (which needs &self).
        let ready_cmds: Vec<String> = {
            match &mut self.mode {
                SessionMode::Command { line_buf } => {
                    let mut cmds = Vec::new();
                    let input = String::from_utf8_lossy(data).to_string();
                    for ch in input.chars() {
                        match ch {
                            '\r' | '\n' => {
                                let cmd = line_buf.trim().to_string();
                                line_buf.clear();
                                if cmd.is_empty() {
                                    session.data(channel, CryptoVec::from(b"$ ".to_vec()));
                                } else {
                                    cmds.push(cmd);
                                }
                            }
                            '\x08' | '\x7f' => {
                                if !line_buf.is_empty() {
                                    line_buf.pop();
                                    session.data(channel, CryptoVec::from(b"\x08 \x08".to_vec()));
                                }
                            }
                            c => {
                                line_buf.push(c);
                                session.data(channel, CryptoVec::from(c.to_string().into_bytes()));
                            }
                        }
                    }
                    cmds
                }
                // All other modes already handled above; this is unreachable.
                _ => vec![],
            }
        }; // ← mutable borrow of self.mode released here

        // Execute collected commands (self is freely borrowable again).
        if !ready_cmds.is_empty() {
            if let Some(user) = self.authed_user.clone() {
                let api = self.api();
                let db_path = self.config.db_path.clone();
                for cmd in ready_cmds {
                    let (output, _) = crate::commands::run(&cmd, &user, &api, &db_path).await;
                    session.data(channel, CryptoVec::from(output.into_bytes()));
                    session.data(channel, CryptoVec::from(b"$ ".to_vec()));
                }
            }
        }

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Window changes for the proxy mode would require forwarding to the VM channel.
        // The vm_channel was moved into spawn_proxy; a follow-up could add a control
        // channel for window changes. Accepted limitation for phase 6.
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(peer = ?self.peer_addr, "channel_close");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(peer = ?self.peer_addr, "channel_eof");
        Ok(())
    }
}

// ── Server factory ────────────────────────────────────────────────────────────

pub struct SshServer {
    pub config: Arc<crate::GatewayConfig>,
}

#[async_trait::async_trait]
impl russh::server::Server for SshServer {
    type Handler = ConnectionHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> ConnectionHandler {
        ConnectionHandler::new(Arc::clone(&self.config), peer_addr)
    }
}
