use anyhow::{Context, Result};
use minions_proto::{read_frame, write_frame, Request, Response, ResponseData};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing::{error, info};

mod exec;
mod network;

const VSOCK_PORT: u32 = 1024;

#[tokio::main]
async fn main() -> Result<()> {
    // Set up logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    info!("minions-agent starting");

    // Bind VSOCK listener on port 1024
    let addr = VsockAddr::new(VMADDR_CID_ANY, VSOCK_PORT);
    let listener = VsockListener::bind(addr).context("failed to bind VSOCK listener")?;

    info!("listening on VSOCK port {}", VSOCK_PORT);

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                info!("accepted connection from {:?}", peer);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&mut stream).await {
                        error!("connection error: {:#}", e);
                    }
                });
            }
            Err(e) => {
                error!("accept error: {:#}", e);
            }
        }
    }
}

async fn handle_connection(stream: &mut tokio_vsock::VsockStream) -> Result<()> {
    loop {
        let request: Request = match read_frame(stream).await {
            Ok(req) => req,
            Err(e) => {
                // Connection closed or read error
                info!("read error (connection likely closed): {:#}", e);
                break;
            }
        };

        info!("received request: {:?}", request);

        let response = handle_request(request).await;

        write_frame(stream, &response)
            .await
            .context("failed to write response")?;

        info!("sent response: {:?}", response);
    }

    Ok(())
}

async fn handle_request(request: Request) -> Response {
    match request {
        Request::HealthCheck => {
            let uptime_secs = read_uptime().unwrap_or(0);
            let hostname = read_hostname().unwrap_or_else(|_| "unknown".to_string());

            Response::ok_with_data(ResponseData::Health {
                uptime_secs,
                hostname,
            })
        }

        Request::ConfigureNetwork { ip, gateway, dns } => {
            match network::configure(&ip, &gateway, &dns).await {
                Ok(_) => Response::ok_with_message("network configured"),
                Err(e) => Response::error(format!("failed to configure network: {:#}", e)),
            }
        }

        Request::Exec { command, args } => match exec::run(&command, &args).await {
            Ok((exit_code, stdout, stderr)) => {
                Response::ok_with_data(ResponseData::Exec {
                    exit_code,
                    stdout,
                    stderr,
                })
            }
            Err(e) => Response::error(format!("failed to execute command: {:#}", e)),
        },

        Request::ReportStatus => {
            let uptime_secs = read_uptime().unwrap_or(0);
            let (memory_total_mb, memory_used_mb) = read_memory().unwrap_or((0, 0));
            let (disk_total_gb, disk_used_gb) = read_disk().unwrap_or((0, 0));

            Response::ok_with_data(ResponseData::Status {
                uptime_secs,
                memory_total_mb,
                memory_used_mb,
                disk_total_gb,
                disk_used_gb,
            })
        }
    }
}

fn read_uptime() -> Result<u64> {
    let content = std::fs::read_to_string("/proc/uptime")?;
    let uptime_str = content.split_whitespace().next().context("empty uptime")?;
    let uptime: f64 = uptime_str.parse()?;
    Ok(uptime as u64)
}

fn read_hostname() -> Result<String> {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .context("failed to read hostname")
}

fn read_memory() -> Result<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/meminfo")?;
    let mut total = 0;
    let mut available = 0;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
                / 1024; // KB -> MB
        } else if line.starts_with("MemAvailable:") {
            available = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
                / 1024; // KB -> MB
        }
    }

    let used = total.saturating_sub(available);
    Ok((total, used))
}

fn read_disk() -> Result<(u64, u64)> {
    use nix::sys::statvfs::statvfs;

    let stats = statvfs("/")?;
    let total = (stats.blocks() * stats.block_size()) / (1024 * 1024 * 1024); // bytes -> GB
    let used = ((stats.blocks() - stats.blocks_available()) * stats.block_size())
        / (1024 * 1024 * 1024);

    Ok((total, used))
}
