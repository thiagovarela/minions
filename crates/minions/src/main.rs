//! `minions` — VM lifecycle CLI + daemon for cloud-hypervisor guests.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::process::Command;
use tabled::{Table, Tabled};

mod agent;
mod api;
mod auth;
mod client;
mod db;
mod hypervisor;
mod init;
mod network;
mod server;
mod storage;
mod vm;

use minions_proto::{Request, Response, ResponseData};

#[derive(Parser)]
#[command(
    name = "minions",
    about = "VM lifecycle manager for cloud-hypervisor guests",
    version
)]
struct Cli {
    /// SQLite database path (direct mode only)
    #[arg(long, default_value = db::DB_PATH, global = true)]
    db: String,

    /// Connect to a remote minions daemon (e.g. http://minipc:3000)
    /// When set, the CLI is a thin HTTP client — no sudo required.
    #[arg(long, global = true)]
    host: Option<String>,

    /// Output results as JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and start a new VM
    Create {
        name: String,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value_t = 1024)]
        memory: u32,
    },
    /// Destroy a running VM (halt + remove rootfs + remove from DB)
    Destroy { name: String },
    /// Stop a VM (halt CH process, keep rootfs + DB record)
    Stop { name: String },
    /// List all VMs
    List,
    /// Restart a running VM (ACPI reboot signal)
    Restart { name: String },
    /// Rename a stopped VM
    Rename { old_name: String, new_name: String },
    /// Copy an existing VM to a new VM
    Cp {
        /// Source VM name
        source: String,
        /// New VM name (auto-generated if omitted)
        new_name: Option<String>,
    },
    /// Run a command inside a VM
    Exec {
        name: String,
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Open an interactive SSH session into a VM
    Ssh { name: String },
    /// Show VM status (from agent)
    Status { name: String },
    /// Print serial console log
    Logs { name: String },
    /// Start the HTTP API daemon
    Serve {
        /// Address to bind the HTTP API to
        #[arg(long, default_value = "0.0.0.0:3000")]
        bind: String,
        /// Address to bind the SSH gateway to (e.g. 0.0.0.0:22)
        /// When set, the SSH gateway starts alongside the HTTP API.
        #[arg(long)]
        ssh_bind: Option<String>,
    },
    /// One-time host setup: bridge, iptables, directories, systemd unit
    Init {
        /// Also persist networking across reboots (sysctl + iptables-persistent)
        #[arg(long)]
        persist: bool,
    },
}

// ── Serialisable VM row (for --json output) ───────────────────────────────────

#[derive(Serialize)]
struct VmJson {
    name: String,
    status: String,
    ip: String,
    cpus: u32,
    memory_mb: u32,
    pid: Option<i64>,
}

impl From<db::Vm> for VmJson {
    fn from(v: db::Vm) -> Self {
        VmJson {
            name: v.name,
            status: v.status,
            ip: v.ip,
            cpus: v.vcpus,
            memory_mb: v.memory_mb,
            pid: v.ch_pid,
        }
    }
}

impl From<client::VmResponse> for VmJson {
    fn from(v: client::VmResponse) -> Self {
        VmJson {
            name: v.name,
            status: v.status,
            ip: v.ip,
            cpus: v.cpus,
            memory_mb: v.memory_mb,
            pid: v.pid,
        }
    }
}

// ── Table row (for human-readable output) ────────────────────────────────────

#[derive(Tabled)]
struct VmRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "STATUS")]
    status: String,
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "CPUS")]
    cpus: u32,
    #[tabled(rename = "MEMORY")]
    memory: String,
    #[tabled(rename = "PID")]
    pid: String,
}

impl From<db::Vm> for VmRow {
    fn from(v: db::Vm) -> Self {
        VmRow {
            name: v.name,
            status: v.status,
            ip: v.ip,
            cpus: v.vcpus,
            memory: format!("{} MiB", v.memory_mb),
            pid: v.ch_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
        }
    }
}

impl From<client::VmResponse> for VmRow {
    fn from(v: client::VmResponse) -> Self {
        VmRow {
            name: v.name,
            status: v.status,
            ip: v.ip,
            cpus: v.cpus,
            memory: format!("{} MiB", v.memory_mb),
            pid: v.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
        }
    }
}

// ── Output helpers ────────────────────────────────────────────────────────────

fn print_vm(vm: VmJson, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&vm).unwrap());
    } else {
        println!();
        println!("✓ VM '{}' is {}", vm.name, vm.status);
        println!("  IP:     {}", vm.ip);
        println!("  CPUs:   {}", vm.cpus);
        println!("  Memory: {} MiB", vm.memory_mb);
        println!("  PID:    {}", vm.pid.unwrap_or(0));
        println!();
        println!("  SSH:    ssh root@{}", vm.ip);
    }
}

fn print_vm_list<I: IntoIterator<Item = VmJson>>(vms: I, json: bool) {
    let vms: Vec<VmJson> = vms.into_iter().collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&vms).unwrap());
    } else {
        if vms.is_empty() {
            println!("No VMs found.");
            return;
        }
        let rows: Vec<VmRow> = vms
            .into_iter()
            .map(|v| VmRow {
                name: v.name,
                status: v.status,
                ip: v.ip,
                cpus: v.cpus,
                memory: format!("{} MiB", v.memory_mb),
                pid: v.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
            })
            .collect();
        println!("{}", Table::new(rows));
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    let json = cli.json;

    // Init and Serve always run directly — they ARE the server side.
    match &cli.command {
        Commands::Init { persist } => return init::run(*persist),
        Commands::Serve { bind, ssh_bind } => {
            let ssh_pubkey = find_ssh_pubkey();
            return server::serve(cli.db.clone(), bind.clone(), ssh_pubkey, ssh_bind.clone()).await;
        }
        // Ssh is always local (interactive terminal).
        Commands::Ssh { name } => return cmd_ssh(&cli.db, name).await,
        _ => {}
    }

    // Determine whether to use HTTP client or direct mode.
    let host = if let Some(h) = &cli.host {
        Some(h.clone())
    } else {
        // Auto-detect: if local daemon is reachable, use it.
        client::local_daemon_url().await
    };

    if let Some(host) = host {
        run_remote(&host, cli.command, json).await
    } else {
        run_direct(&cli.db, cli.command, json).await
    }
}

// ── Remote mode (HTTP client) ─────────────────────────────────────────────────

async fn run_remote(host: &str, command: Commands, json: bool) -> Result<()> {
    let c = client::Client::new(host);

    match command {
        Commands::Create { name, cpus, memory } => {
            if !json {
                println!("Creating VM '{name}' via {host}…");
            }
            let vm = c
                .create_vm(client::CreateRequest { name, cpus, memory_mb: memory })
                .await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Destroy { name } => {
            if !json {
                println!("Destroying VM '{name}' via {host}…");
            }
            c.destroy_vm(&name).await?;
            if json {
                println!("{}", serde_json::json!({ "message": format!("VM '{name}' destroyed") }));
            } else {
                println!("✓ VM '{name}' destroyed");
            }
        }

        Commands::List => {
            let vms = c.list_vms().await?;
            print_vm_list(vms.into_iter().map(VmJson::from), json);
        }

        Commands::Stop { name } => {
            if !json {
                println!("Stopping VM '{name}' via {host}…");
            }
            let vm = c.stop_vm(&name).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Restart { name } => {
            if !json {
                println!("Restarting VM '{name}' via {host}…");
            }
            let vm = c.restart_vm(&name).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Rename { old_name, new_name } => {
            if !json {
                println!("Renaming VM '{old_name}' → '{new_name}' via {host}…");
            }
            c.rename_vm(&old_name, &new_name).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "message": format!("VM '{old_name}' renamed to '{new_name}'") })
                );
            } else {
                println!("✓ VM '{old_name}' renamed to '{new_name}'");
            }
        }

        Commands::Cp { source, new_name } => {
            let new_name = resolve_copy_name(&source, new_name);
            if !json {
                println!("Copying VM '{source}' → '{new_name}' via {host}…");
            }
            let vm = c.copy_vm(&source, &new_name).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Exec { name, cmd } => {
            if cmd.is_empty() {
                anyhow::bail!("provide a command after --");
            }
            let resp = c
                .exec_vm(
                    &name,
                    client::ExecRequest { command: cmd[0].clone(), args: cmd[1..].to_vec() },
                )
                .await?;
            if !resp.stdout.is_empty() { print!("{}", resp.stdout); }
            if !resp.stderr.is_empty() { eprint!("{}", resp.stderr); }
            if resp.exit_code != 0 {
                std::process::exit(resp.exit_code);
            }
        }

        Commands::Status { name } => {
            let status = c.vm_status(&name).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }

        Commands::Logs { name } => {
            let logs = c.vm_logs(&name).await?;
            print!("{logs}");
        }

        // Already handled above or unreachable in remote mode.
        _ => unreachable!(),
    }

    Ok(())
}

// ── Direct mode (local orchestration) ────────────────────────────────────────

async fn run_direct(db_path: &str, command: Commands, json: bool) -> Result<()> {
    match command {
        Commands::Create { name, cpus, memory } => {
            if !json {
                println!("Creating VM '{name}'…");
            }
            let ssh_pubkey = find_ssh_pubkey();
            if ssh_pubkey.is_some() && !json {
                println!("  (SSH public key found — key-based SSH will work)");
            }
            let vm = vm::create(db_path, &name, cpus, memory, ssh_pubkey).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Destroy { name } => {
            if !json {
                println!("Destroying VM '{name}'…");
            }
            vm::destroy(db_path, &name).await?;
            if json {
                println!("{}", serde_json::json!({ "message": format!("VM '{name}' destroyed") }));
            } else {
                println!("✓ VM '{name}' destroyed");
            }
        }

        Commands::List => {
            let conn = db::open(db_path).context("open state database")?;
            let vms = vm::list(&conn)?;
            print_vm_list(vms.into_iter().map(VmJson::from), json);
        }

        Commands::Stop { name } => {
            if !json {
                println!("Stopping VM '{name}'…");
            }
            let vm = vm::stop(db_path, &name).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Restart { name } => {
            if !json {
                println!("Restarting VM '{name}'…");
            }
            let vm = vm::restart(db_path, &name).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Rename { old_name, new_name } => {
            if !json {
                println!("Renaming VM '{old_name}' → '{new_name}'…");
            }
            vm::rename(db_path, &old_name, &new_name).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "message": format!("VM '{old_name}' renamed to '{new_name}'") })
                );
            } else {
                println!("✓ VM '{old_name}' renamed to '{new_name}'");
            }
        }

        Commands::Cp { source, new_name } => {
            let new_name = resolve_copy_name(&source, new_name);
            if !json {
                println!("Copying VM '{source}' → '{new_name}'…");
            }
            let ssh_pubkey = find_ssh_pubkey();
            let vm = vm::copy(db_path, &source, &new_name, ssh_pubkey).await?;
            print_vm(VmJson::from(vm), json);
        }

        Commands::Exec { name, cmd } => {
            if cmd.is_empty() {
                anyhow::bail!("provide a command after --");
            }
            // Drop conn before await.
            let vsock_socket = {
                let conn = db::open(db_path).context("open state database")?;
                let vm_rec = db::get_vm(&conn, &name)?
                    .with_context(|| format!("VM '{name}' not found"))?;
                std::path::PathBuf::from(vm_rec.ch_vsock_socket)
            };

            let response = agent::send_request(
                &vsock_socket,
                Request::Exec { command: cmd[0].clone(), args: cmd[1..].to_vec() },
            )
            .await?;

            match response {
                Response::Ok {
                    data: Some(ResponseData::Exec { exit_code, stdout, stderr }),
                    ..
                } => {
                    if !stdout.is_empty() { print!("{stdout}"); }
                    if !stderr.is_empty() { eprint!("{stderr}"); }
                    if exit_code != 0 { std::process::exit(exit_code); }
                }
                Response::Error { message } => anyhow::bail!("exec error: {message}"),
                other => anyhow::bail!("unexpected response: {other:?}"),
            }
        }

        Commands::Status { name } => {
            // Drop conn before await.
            let vsock_socket = {
                let conn = db::open(db_path).context("open state database")?;
                let vm_rec = db::get_vm(&conn, &name)?
                    .with_context(|| format!("VM '{name}' not found"))?;
                std::path::PathBuf::from(vm_rec.ch_vsock_socket)
            };
            let response = agent::send_request(&vsock_socket, Request::ReportStatus).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }

        Commands::Logs { name } => {
            let log_path = storage::serial_log_path(&name);
            if !log_path.exists() {
                anyhow::bail!("no serial log found at {}", log_path.display());
            }
            print!("{}", std::fs::read_to_string(&log_path)?);
        }

        _ => unreachable!(),
    }

    Ok(())
}

// ── SSH (always local) ────────────────────────────────────────────────────────

async fn cmd_ssh(db_path: &str, name: &str) -> Result<()> {
    let conn = db::open(db_path).context("open state database")?;
    let vm_rec = db::get_vm(&conn, name)?
        .with_context(|| format!("VM '{name}' not found"))?;

    let mut ssh_args: Vec<String> = vec![
        "-o".into(), "StrictHostKeyChecking=no".into(),
        "-o".into(), "UserKnownHostsFile=/dev/null".into(),
    ];
    if let Some(key_path) = find_ssh_identity_path() {
        ssh_args.push("-i".into());
        ssh_args.push(key_path);
    }
    ssh_args.push(format!("root@{}", vm_rec.ip));

    let status = Command::new("ssh").args(&ssh_args).status().context("exec ssh")?;
    std::process::exit(status.code().unwrap_or(1));
}

// ── Copy name resolution ──────────────────────────────────────────────────────

/// Derive a name for a copied VM if the user didn't supply one.
///
/// Strategy: append `-copy`, then `-copy2`, `-copy3` … but without hitting
/// the DB (the VM manager will reject duplicates if there's a collision).
/// Keep it under the 11-char TAP limit.
fn resolve_copy_name(source: &str, new_name: Option<String>) -> String {
    if let Some(n) = new_name {
        return n;
    }
    // Truncate source to leave room for "-copy" suffix (5 chars → max 6 source chars)
    let max_base = 11 - 5; // 6
    let base = if source.len() > max_base { &source[..max_base] } else { source };
    format!("{base}-copy")
}

// ── SSH key discovery ─────────────────────────────────────────────────────────

fn find_ssh_pubkey() -> Option<String> {
    // 1. Explicit path via env var (used by the systemd daemon, which runs as root).
    if let Ok(path) = std::env::var("MINIONS_SSH_PUBKEY_PATH") {
        if let Ok(key) = std::fs::read_to_string(&path) {
            let key = key.trim().to_string();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }

    // 2. Inline key via env var.
    if let Ok(key) = std::env::var("MINIONS_SSH_PUBKEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Some(key);
        }
    }

    // 3. Discover from the invoking user's ~/.ssh/ directory.
    let ssh_dir = ssh_dir_for_invoking_user()?;
    for name in &["id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"] {
        let path = ssh_dir.join(name);
        if let Ok(key) = std::fs::read_to_string(&path) {
            let key = key.trim().to_string();
            if !key.is_empty() {
                return Some(key);
            }
        }
    }
    None
}

fn find_ssh_identity_path() -> Option<String> {
    let ssh_dir = ssh_dir_for_invoking_user()?;
    for name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
        let path = ssh_dir.join(name);
        if path.exists() {
            return Some(path.to_string_lossy().into_owned());
        }
    }
    None
}

fn ssh_dir_for_invoking_user() -> Option<std::path::PathBuf> {
    let user = std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty());
    if let Some(ref u) = user {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let fields: Vec<&str> = line.splitn(7, ':').collect();
                if fields.len() >= 6 && fields[0] == u {
                    return Some(std::path::PathBuf::from(fields[5]).join(".ssh"));
                }
            }
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".ssh"))
}
