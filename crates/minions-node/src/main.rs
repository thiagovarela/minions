//! Standalone node agent daemon.
//!
//! Runs an HTTP API server that the control plane can call to manage VMs on
//! this host. This is used in multi-host deployments where the control plane
//! and node agents run on separate machines.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

mod agent;
mod hypervisor;
mod network;
mod storage;
mod vm;

#[derive(Clone)]
struct AppState {
    db_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("MINIONS_DB_PATH")
        .unwrap_or_else(|_| "/var/lib/minions/state.db".to_string());

    let state = Arc::new(AppState { db_path });

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/vms", post(create_vm))
        .route("/vms/:name", delete(destroy_vm))
        .route("/vms/:name/stop", post(stop_vm))
        .route("/vms/:name/start", post(start_vm))
        .route("/vms/:name/restart", post(restart_vm))
        .route("/vms/:name/snapshot", post(snapshot_vm))
        .route("/vms/:name/exec", post(exec_vm))
        .with_state(state);

    let addr = "0.0.0.0:5001";
    info!("minions-node agent listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct StatusResponse {
    total_vcpus: u32,
    total_memory_mb: u32,
    total_disk_gb: u32,
    available_vcpus: u32,
    available_memory_mb: u32,
    available_disk_gb: u32,
    vm_count: usize,
}

async fn status(State(state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, AppError> {
    // TODO: Implement actual resource tracking
    // For now, return hardcoded capacity
    Ok(Json(StatusResponse {
        total_vcpus: 32,
        total_memory_mb: 32768,
        total_disk_gb: 500,
        available_vcpus: 32,
        available_memory_mb: 32768,
        available_disk_gb: 500,
        vm_count: 0,
    }))
}

#[derive(Deserialize)]
struct CreateVmRequest {
    name: String,
    vcpus: u32,
    memory_mb: u32,
    ssh_pubkey: Option<String>,
    owner_id: Option<String>,
}

async fn create_vm(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateVmRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Creating VM: {}", req.name);
    let vm = vm::create(
        &state.db_path,
        &req.name,
        req.vcpus,
        req.memory_mb,
        req.ssh_pubkey,
        req.owner_id,
    )
    .await?;
    Ok(Json(serde_json::json!(vm)))
}

async fn destroy_vm(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    info!("Destroying VM: {}", name);
    vm::destroy(&state.db_path, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn stop_vm(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Stopping VM: {}", name);
    let vm = vm::stop(&state.db_path, &name).await?;
    Ok(Json(serde_json::json!(vm)))
}

async fn start_vm(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Starting VM: {}", name);
    let vm = vm::start(&state.db_path, &name).await?;
    Ok(Json(serde_json::json!(vm)))
}

async fn restart_vm(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Restarting VM: {}", name);
    let vm = vm::restart(&state.db_path, &name).await?;
    Ok(Json(serde_json::json!(vm)))
}

#[derive(Deserialize)]
struct SnapshotRequest {
    name: Option<String>,
}

async fn snapshot_vm(
    State(state): State<Arc<AppState>>,
    Path(vm_name): Path<String>,
    Json(req): Json<SnapshotRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Creating snapshot for VM: {}", vm_name);
    let snapshot = vm::snapshot(&state.db_path, &vm_name, req.name).await?;
    Ok(Json(serde_json::json!(snapshot)))
}

#[derive(Deserialize)]
struct ExecRequest {
    command: String,
    args: Vec<String>,
}

async fn exec_vm(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("Executing command in VM {}: {} {:?}", name, req.command, req.args);
    
    // Get VM vsock socket
    let vsock_socket = {
        use rusqlite::Connection;
        let conn = Connection::open(&state.db_path)?;
        let vm = crate::db::get_vm(&conn, &name)?
            .ok_or_else(|| anyhow::anyhow!("VM '{}' not found", name))?;
        std::path::PathBuf::from(vm.ch_vsock_socket)
    };

    let response = agent::send_request(
        &vsock_socket,
        minions_proto::Request::Exec {
            command: req.command,
            args: req.args,
        },
    )
    .await?;

    Ok(Json(serde_json::json!(response)))
}

// Error handling
struct AppError(anyhow::Error);

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error: {:#}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

// Stub database functions (will be moved/shared later)
mod db {
    use anyhow::{Context, Result};
    use rusqlite::Connection;

    pub struct Vm {
        pub ch_vsock_socket: String,
    }

    pub fn get_vm(conn: &Connection, name: &str) -> Result<Option<Vm>> {
        let mut stmt = conn
            .prepare("SELECT ch_vsock_socket FROM vms WHERE name = ?1")
            .context("prepare get_vm")?;
        
        let vm = stmt
            .query_row([name], |row| {
                Ok(Vm {
                    ch_vsock_socket: row.get(0)?,
                })
            })
            .optional()
            .context("query get_vm")?;
        
        Ok(vm)
    }
}
