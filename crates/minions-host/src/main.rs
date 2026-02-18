use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use minions_proto::{read_frame, write_frame, Request, Response};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[derive(Parser)]
#[command(name = "minions-host")]
#[command(about = "Test CLI for communicating with minions-agent via VSOCK")]
struct Cli {
    /// Path to the Cloud Hypervisor VSOCK Unix socket
    #[arg(short, long, default_value = "/run/minions/test-vm.vsock")]
    socket: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Health check
    Health,

    /// Configure network
    ConfigureNetwork {
        /// IP address with CIDR (e.g. 10.0.0.2/16)
        #[arg(long)]
        ip: String,

        /// Gateway IP
        #[arg(long)]
        gateway: String,

        /// DNS servers
        #[arg(long, value_delimiter = ',', default_value = "1.1.1.1,8.8.8.8")]
        dns: Vec<String>,
    },

    /// Execute a command
    Exec {
        /// Command to run
        command: String,

        /// Arguments
        args: Vec<String>,
    },

    /// Report system status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Connect to VSOCK Unix socket
    let mut stream = UnixStream::connect(&cli.socket)
        .await
        .with_context(|| format!("failed to connect to {:?}", cli.socket))?;

    // Send VSOCK CONNECT handshake
    stream
        .write_all(b"CONNECT 1024\n")
        .await
        .context("failed to send CONNECT")?;

    // Read OK response
    let mut reader = BufReader::new(&mut stream);
    let mut ok_line = String::new();
    reader
        .read_line(&mut ok_line)
        .await
        .context("failed to read OK response")?;

    if !ok_line.starts_with("OK ") {
        anyhow::bail!("unexpected response: {}", ok_line.trim());
    }

    // Now we have a bidirectional stream connected to the agent
    let mut stream = reader.into_inner();

    // Build and send the request
    let request = match cli.command {
        Commands::Health => Request::HealthCheck,
        Commands::ConfigureNetwork { ip, gateway, dns } => {
            Request::ConfigureNetwork { ip, gateway, dns }
        }
        Commands::Exec { command, args } => Request::Exec { command, args },
        Commands::Status => Request::ReportStatus,
    };

    write_frame(&mut stream, &request)
        .await
        .context("failed to send request")?;

    // Read the response
    let response: Response = read_frame(&mut stream)
        .await
        .context("failed to read response")?;

    // Display the response
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
