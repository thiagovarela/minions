//! `minions` — VM lifecycle CLI for cloud-hypervisor guests.
//!
//! Must be run as root.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use minions_proto::{Request, Response, ResponseData};
use std::process::Command;
use tabled::{Table, Tabled};

mod agent;
mod db;
mod hypervisor;
mod network;
mod storage;
mod vm;

#[derive(Parser)]
#[command(
    name = "minions",
    about = "VM lifecycle manager for cloud-hypervisor guests",
    version
)]
struct Cli {
    /// SQLite database path
    #[arg(long, default_value = db::DB_PATH)]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and start a new VM
    Create {
        /// VM name (alphanumeric + hyphens, max 11 chars)
        name: String,

        /// Number of vCPUs
        #[arg(long, default_value_t = 2)]
        cpus: u32,

        /// Memory in MiB
        #[arg(long, default_value_t = 1024)]
        memory: u32,
    },

    /// Destroy a running VM
    Destroy {
        /// VM name
        name: String,
    },

    /// List all VMs
    List,

    /// Run a command inside a VM
    Exec {
        /// VM name
        name: String,

        /// Command and arguments (after --)
        #[arg(last = true)]
        cmd: Vec<String>,
    },

    /// Open an interactive SSH session into a VM
    Ssh {
        /// VM name
        name: String,
    },

    /// Show VM status (from agent)
    Status {
        /// VM name
        name: String,
    },

    /// Print serial console log of a VM
    Logs {
        /// VM name
        name: String,
    },
}

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let cli = Cli::parse();
    let conn = db::open(&cli.db).context("open state database")?;

    match cli.command {
        Commands::Create { name, cpus, memory } => {
            println!("Creating VM '{name}'…");
            let ssh_pubkey = find_ssh_pubkey();
            if ssh_pubkey.is_some() {
                println!("  (SSH public key found — key-based SSH will work)");
            }
            let vm = vm::create(&conn, &name, cpus, memory, ssh_pubkey).await?;
            println!();
            println!("✓ VM '{name}' is running");
            println!("  IP:     {}", vm.ip);
            println!("  CID:    {}", vm.vsock_cid);
            println!("  CPUs:   {}", vm.vcpus);
            println!("  Memory: {} MiB", vm.memory_mb);
            println!("  PID:    {}", vm.ch_pid.unwrap_or(0));
            println!();
            println!("  SSH:    ssh root@{}", vm.ip);
        }

        Commands::Destroy { name } => {
            println!("Destroying VM '{name}'…");
            vm::destroy(&conn, &name).await?;
            println!("✓ VM '{name}' destroyed");
        }

        Commands::List => {
            let vms = vm::list(&conn)?;
            if vms.is_empty() {
                println!("No VMs found.");
            } else {
                let rows: Vec<VmRow> = vms
                    .into_iter()
                    .map(|v| VmRow {
                        name: v.name,
                        status: v.status,
                        ip: v.ip,
                        cpus: v.vcpus,
                        memory: format!("{} MiB", v.memory_mb),
                        pid: v
                            .ch_pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    })
                    .collect();
                println!("{}", Table::new(rows));
            }
        }

        Commands::Exec { name, cmd } => {
            if cmd.is_empty() {
                anyhow::bail!("provide a command after --");
            }
            let vm_rec = db::get_vm(&conn, &name)?
                .with_context(|| format!("VM '{name}' not found"))?;

            let vsock_socket = std::path::PathBuf::from(&vm_rec.ch_vsock_socket);
            let response = agent::send_request(
                &vsock_socket,
                Request::Exec {
                    command: cmd[0].clone(),
                    args: cmd[1..].to_vec(),
                },
            )
            .await?;

            match response {
                Response::Ok {
                    data: Some(ResponseData::Exec { exit_code, stdout, stderr }),
                    ..
                } => {
                    if !stdout.is_empty() {
                        print!("{stdout}");
                    }
                    if !stderr.is_empty() {
                        eprint!("{stderr}");
                    }
                    if exit_code != 0 {
                        std::process::exit(exit_code);
                    }
                }
                Response::Error { message } => anyhow::bail!("exec error: {message}"),
                other => anyhow::bail!("unexpected response: {:?}", other),
            }
        }

        Commands::Ssh { name } => {
            let vm_rec = db::get_vm(&conn, &name)?
                .with_context(|| format!("VM '{name}' not found"))?;

            // Build ssh args; if SUDO_USER has a key, point at it explicitly.
            let mut ssh_args: Vec<String> = vec![
                "-o".into(),
                "StrictHostKeyChecking=no".into(),
                "-o".into(),
                "UserKnownHostsFile=/dev/null".into(),
            ];
            if let Some(key_path) = find_ssh_identity_path() {
                ssh_args.push("-i".into());
                ssh_args.push(key_path);
            }
            ssh_args.push(format!("root@{}", vm_rec.ip));

            let status = Command::new("ssh")
                .args(&ssh_args)
                .status()
                .context("exec ssh")?;
            std::process::exit(status.code().unwrap_or(1));
        }

        Commands::Status { name } => {
            let vm_rec = db::get_vm(&conn, &name)?
                .with_context(|| format!("VM '{name}' not found"))?;
            let vsock_socket = std::path::PathBuf::from(&vm_rec.ch_vsock_socket);
            let response =
                agent::send_request(&vsock_socket, Request::ReportStatus).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }

        Commands::Logs { name } => {
            let log_path = storage::serial_log_path(&name);
            if !log_path.exists() {
                anyhow::bail!("no serial log found at {}", log_path.display());
            }
            let content = std::fs::read_to_string(&log_path)?;
            print!("{content}");
        }
    }

    Ok(())
}

/// Find the SSH public key of the invoking user (works under sudo).
/// Tries common key file names in the user's ~/.ssh directory.
fn find_ssh_pubkey() -> Option<String> {
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

/// Return the path to the private key identity file for the invoking user.
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

/// Return the ~/.ssh directory of the user who invoked sudo (or current user).
fn ssh_dir_for_invoking_user() -> Option<std::path::PathBuf> {
    // When running under sudo, SUDO_USER is the original user.
    let user = std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty());
    if let Some(ref u) = user {
        // Look up home directory via /etc/passwd.
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let fields: Vec<&str> = line.splitn(7, ':').collect();
                if fields.len() >= 6 && fields[0] == u {
                    return Some(std::path::PathBuf::from(fields[5]).join(".ssh"));
                }
            }
        }
    }
    // Fallback: current user's home.
    std::env::var("HOME")
        .ok()
        .map(|h| std::path::PathBuf::from(h).join(".ssh"))
}
