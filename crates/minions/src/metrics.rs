//! Metrics collection and Prometheus text exposition.
//!
//! A background tokio task polls every running VM's guest agent periodically
//! and stores the results in a shared in-memory snapshot. The `/metrics`
//! HTTP endpoint serialises the snapshot into Prometheus text format.
//!
//! No external Prometheus library is used — the text format is straightforward
//! enough to produce directly.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tracing::{debug, warn};

use crate::{agent, db};
use minions_proto::{Request, Response, ResponseData};

// ── Per-VM snapshot ───────────────────────────────────────────────────────────

/// Metrics snapshot for a single VM, collected from the guest agent.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VmMetrics {
    pub vm_name: String,
    pub owner_id: Option<String>,
    pub status: String,
    pub uptime_secs: u64,
    pub cpu_usage_percent: f64,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub disk_total_gb: u64,
    pub disk_used_gb: u64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub load_avg_1m: f64,
    /// Unix timestamp when this snapshot was last updated.
    pub collected_at_secs: u64,
}

// ── Host-level snapshot ───────────────────────────────────────────────────────

/// Host-level metrics (the bare metal machine running all VMs).
#[derive(Debug, Clone, Default, Serialize)]
pub struct HostMetrics {
    pub vm_count_running: u32,
    pub vm_count_stopped: u32,
    pub vm_count_error: u32,
}

// ── Shared store ──────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Inner {
    vms: HashMap<String, VmMetrics>,
    host: HostMetrics,
}

/// Thread-safe, cheaply-cloneable metrics store.
#[derive(Clone, Default)]
pub struct MetricsStore(Arc<RwLock<Inner>>);

impl MetricsStore {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(Inner::default())))
    }

    /// Overwrite the snapshot for one VM.
    fn update_vm(&self, m: VmMetrics) {
        if let Ok(mut inner) = self.0.write() {
            inner.vms.insert(m.vm_name.clone(), m);
        }
    }

    /// Overwrite host-level counters.
    fn update_host(&self, h: HostMetrics) {
        if let Ok(mut inner) = self.0.write() {
            inner.host = h;
        }
    }

    /// Snapshot for a specific VM (for the `/api/vms/{name}/metrics` endpoint).
    pub fn get_vm(&self, name: &str) -> Option<VmMetrics> {
        self.0.read().ok()?.vms.get(name).cloned()
    }

    /// All VM snapshots (for Prometheus scrape).
    pub fn all_vms(&self) -> Vec<VmMetrics> {
        self.0
            .read()
            .ok()
            .map(|inner| inner.vms.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn host(&self) -> HostMetrics {
        self.0
            .read()
            .ok()
            .map(|inner| inner.host.clone())
            .unwrap_or_default()
    }
}

// ── Background collector ──────────────────────────────────────────────────────

/// Spawn the metrics collection loop. Call once from `server::serve()`.
pub fn spawn_collector(db_path: String, store: MetricsStore, interval_secs: u64) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(interval_secs);
        loop {
            collect_once(&db_path, &store).await;
            tokio::time::sleep(interval).await;
        }
    });
}

async fn collect_once(db_path: &str, store: &MetricsStore) {
    let vms = match db::open(db_path).and_then(|c| db::list_vms(&c)) {
        Ok(v) => v,
        Err(e) => {
            warn!("metrics: failed to list VMs: {e:#}");
            return;
        }
    };

    let mut running = 0u32;
    let mut stopped = 0u32;
    let mut error = 0u32;

    for vm in &vms {
        match vm.status.as_str() {
            "running" => running += 1,
            "stopped" => stopped += 1,
            _ => error += 1,
        }
    }

    store.update_host(HostMetrics {
        vm_count_running: running,
        vm_count_stopped: stopped,
        vm_count_error: error,
    });

    // Poll running VMs in parallel (with a per-VM timeout).
    let tasks: Vec<_> = vms
        .into_iter()
        .filter(|v| v.status == "running")
        .map(|vm| {
            let store = store.clone();
            let vsock = std::path::PathBuf::from(&vm.ch_vsock_socket);
            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    agent::send_request(&vsock, Request::ReportStatus),
                )
                .await;

                match result {
                    Ok(Ok(Response::Ok {
                        data:
                            Some(ResponseData::Status {
                                uptime_secs,
                                memory_total_mb,
                                memory_used_mb,
                                disk_total_gb,
                                disk_used_gb,
                                cpu_usage_percent,
                                network_rx_bytes,
                                network_tx_bytes,
                                load_avg_1m,
                            }),
                        ..
                    })) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        store.update_vm(VmMetrics {
                            vm_name: vm.name.clone(),
                            owner_id: vm.owner_id.clone(),
                            status: vm.status.clone(),
                            uptime_secs,
                            cpu_usage_percent,
                            memory_total_mb,
                            memory_used_mb,
                            disk_total_gb,
                            disk_used_gb,
                            network_rx_bytes,
                            network_tx_bytes,
                            load_avg_1m,
                            collected_at_secs: now,
                        });
                        debug!(vm = %vm.name, cpu = cpu_usage_percent, "metrics collected");
                    }
                    Ok(Ok(_)) => debug!(vm = %vm.name, "unexpected agent response"),
                    Ok(Err(e)) => debug!(vm = %vm.name, "agent error: {e}"),
                    Err(_) => debug!(vm = %vm.name, "agent poll timed out"),
                }
            })
        })
        .collect();

    for t in tasks {
        let _ = t.await;
    }
}

// ── Prometheus text format ────────────────────────────────────────────────────

/// Render all collected metrics as a Prometheus text exposition (Content-Type:
/// text/plain; version=0.0.4).
pub fn prometheus_text(store: &MetricsStore) -> String {
    let mut out = String::with_capacity(4096);
    let host = store.host();

    // Host-level gauges.
    metric(
        &mut out,
        "minions_vms_total",
        "gauge",
        "Number of VMs by status",
        &[
            (vec![("status", "running")], host.vm_count_running as f64),
            (vec![("status", "stopped")], host.vm_count_stopped as f64),
            (vec![("status", "error")], host.vm_count_error as f64),
        ],
    );

    // Per-VM gauges.
    let vms = store.all_vms();

    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_cpu_percent",
        "CPU usage percentage",
        |m| m.cpu_usage_percent,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_memory_used_bytes",
        "Memory used in bytes",
        |m| (m.memory_used_mb * 1024 * 1024) as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_memory_total_bytes",
        "Memory total in bytes",
        |m| (m.memory_total_mb * 1024 * 1024) as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_disk_used_bytes",
        "Disk used in bytes",
        |m| (m.disk_used_gb * 1024 * 1024 * 1024) as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_disk_total_bytes",
        "Disk total in bytes",
        |m| (m.disk_total_gb * 1024 * 1024 * 1024) as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_network_rx_bytes_total",
        "Network bytes received",
        |m| m.network_rx_bytes as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_network_tx_bytes_total",
        "Network bytes transmitted",
        |m| m.network_tx_bytes as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_uptime_seconds",
        "VM uptime in seconds",
        |m| m.uptime_secs as f64,
    );
    per_vm_gauge(
        &mut out,
        &vms,
        "minions_vm_load_avg_1m",
        "1-minute load average",
        |m| m.load_avg_1m,
    );

    out
}

fn metric(
    out: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    samples: &[(Vec<(&str, &str)>, f64)],
) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} {kind}\n"));
    for (labels, value) in samples {
        let label_str = labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        if label_str.is_empty() {
            out.push_str(&format!("{name} {value}\n"));
        } else {
            out.push_str(&format!("{name}{{{label_str}}} {value}\n"));
        }
    }
}

fn per_vm_gauge(
    out: &mut String,
    vms: &[VmMetrics],
    name: &str,
    help: &str,
    extract: impl Fn(&VmMetrics) -> f64,
) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    for vm in vms {
        let owner = vm.owner_id.as_deref().unwrap_or("system");
        let value = extract(vm);
        out.push_str(&format!(
            "{name}{{vm=\"{}\",owner=\"{owner}\"}} {value}\n",
            vm.vm_name
        ));
    }
}
