use anyhow::{Context, Result};
use minions_proto::{Request, Response, ResponseData, read_frame, write_frame};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};
use tracing::{error, info};

mod exec;
mod file;
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
            Ok((exit_code, stdout, stderr)) => Response::ok_with_data(ResponseData::Exec {
                exit_code,
                stdout,
                stderr,
            }),
            Err(e) => Response::error(format!("failed to execute command: {:#}", e)),
        },

        Request::ReportStatus => {
            let uptime_secs = read_uptime().unwrap_or(0);
            let (memory_total_mb, memory_used_mb) = read_memory().unwrap_or((0, 0));
            let (disk_total_gb, disk_used_gb) = read_disk().unwrap_or((0, 0));
            let cpu_usage_percent = read_cpu_usage().await.unwrap_or(0.0);
            let (network_rx_bytes, network_tx_bytes) = read_network().unwrap_or((0, 0));
            let load_avg_1m = read_loadavg().unwrap_or(0.0);

            Response::ok_with_data(ResponseData::Status {
                uptime_secs,
                memory_total_mb,
                memory_used_mb,
                disk_total_gb,
                disk_used_gb,
                cpu_usage_percent,
                network_rx_bytes,
                network_tx_bytes,
                load_avg_1m,
            })
        }

        Request::WriteFile {
            path,
            content,
            mode,
            append,
        } => match file::write_file(&path, &content, mode, append) {
            Ok(_) => {
                Response::ok_with_message(format!("wrote {} bytes to {}", content.len(), path))
            }
            Err(e) => Response::error(format!("failed to write file: {:#}", e)),
        },
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
    let total = (stats.blocks() as u64 * stats.block_size() as u64) / (1024 * 1024 * 1024); // bytes -> GB
    let used = ((stats.blocks() - stats.blocks_available()) as u64 * stats.block_size() as u64)
        / (1024 * 1024 * 1024);

    Ok((total, used))
}

/// Measure CPU usage by sampling /proc/stat twice with a 150ms gap.
/// Returns a percentage across all CPUs (0.0–100.0).
async fn read_cpu_usage() -> Result<f64> {
    fn read_cpu_ticks() -> Result<(u64, u64)> {
        let content = std::fs::read_to_string("/proc/stat")?;
        let line = content.lines().next().unwrap_or("");
        // cpu  user nice system idle iowait irq softirq steal guest guest_nice
        let fields: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if fields.len() < 4 {
            anyhow::bail!("unexpected /proc/stat format");
        }
        let idle = fields[3];
        let total: u64 = fields.iter().sum();
        Ok((idle, total))
    }

    let (idle1, total1) = read_cpu_ticks()?;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let (idle2, total2) = read_cpu_ticks()?;

    let d_total = total2.saturating_sub(total1) as f64;
    let d_idle = idle2.saturating_sub(idle1) as f64;
    if d_total == 0.0 {
        return Ok(0.0);
    }
    Ok(((d_total - d_idle) / d_total * 100.0).clamp(0.0, 100.0))
}

/// Read network bytes from /proc/net/dev for the first non-loopback interface.
fn read_network() -> Result<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/net/dev")?;
    for line in content.lines().skip(2) {
        let line = line.trim();
        if line.starts_with("lo:") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        // Format: iface: rx_bytes packets errs drop fifo frame compressed multicast
        //         tx_bytes tx_packets ...
        // Column indices (0-based): 0=iface 1=rx_bytes 9=tx_bytes
        let rx: u64 = parts[1].parse().unwrap_or(0);
        let tx: u64 = parts[9].parse().unwrap_or(0);
        return Ok((rx, tx));
    }
    Ok((0, 0))
}

/// Read 1-minute load average from /proc/loadavg.
fn read_loadavg() -> Result<f64> {
    let content = std::fs::read_to_string("/proc/loadavg")?;
    let load: f64 = content
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    Ok(load)
}
