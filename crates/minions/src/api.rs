//! HTTP API routes (axum).
//!
//! All responses are JSON. Errors use standard HTTP status codes.
//! Each handler opens its own SQLite connection (WAL mode → safe concurrent reads).

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{agent, db, server::AppState, storage, vm};
use minions_proto::{Request as AgentRequest, Response as AgentResponse, ResponseData};

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/vms", post(create_vm))
        .route("/api/vms", get(list_vms))
        .route("/api/vms/{name}", get(get_vm))
        .route("/api/vms/{name}", delete(destroy_vm))
        .route("/api/vms/{name}/exec", post(exec_vm))
        .route("/api/vms/{name}/status", get(vm_status))
        .route("/api/vms/{name}/logs", get(vm_logs))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub name: String,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_memory")]
    pub memory_mb: u32,
}

fn default_cpus() -> u32 { 2 }
fn default_memory() -> u32 { 1024 }

#[derive(Debug, Serialize)]
pub struct VmResponse {
    pub name: String,
    pub status: String,
    pub ip: String,
    pub vsock_cid: u32,
    pub cpus: u32,
    pub memory_mb: u32,
    pub pid: Option<i64>,
    pub created_at: String,
}

impl From<db::Vm> for VmResponse {
    fn from(v: db::Vm) -> Self {
        VmResponse {
            name: v.name,
            status: v.status,
            ip: v.ip,
            vsock_cid: v.vsock_cid,
            cpus: v.vcpus,
            memory_mb: v.memory_mb,
            pid: v.ch_pid,
            created_at: v.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse { error: e.to_string() }),
    )
}

fn not_found(name: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: format!("VM '{name}' not found") }),
    )
}

fn bad_request(msg: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse { error: msg.to_string() }),
    )
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `POST /api/vms` — Create a VM.
async fn create_vm(
    State(state): State<AppState>,
    Json(req): Json<CreateRequest>,
) -> impl IntoResponse {
    info!(name = %req.name, cpus = req.cpus, memory_mb = req.memory_mb, "create VM");

    let ssh_pubkey = state.ssh_pubkey.as_deref().map(|s| s.to_string());
    let db_path = state.db_path.as_str().to_string();

    match vm::create(&db_path, &req.name, req.cpus, req.memory_mb, ssh_pubkey).await {
        Ok(v) => (StatusCode::CREATED, Json(VmResponse::from(v))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already exists") {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `GET /api/vms` — List all VMs.
async fn list_vms(State(state): State<AppState>) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    match vm::list(&conn) {
        Ok(vms) => {
            let resp: Vec<VmResponse> = vms.into_iter().map(VmResponse::from).collect();
            Json(resp).into_response()
        }
        Err(e) => internal(e).into_response(),
    }
}

/// `GET /api/vms/:name` — Get VM details.
async fn get_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    match db::get_vm(&conn, &name) {
        Ok(Some(v)) => Json(VmResponse::from(v)).into_response(),
        Ok(None) => not_found(&name).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `DELETE /api/vms/:name` — Destroy a VM.
async fn destroy_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    info!(name = %name, "destroy VM");

    // Check VM exists (sync, connection dropped before await).
    {
        let conn = match db::open(&state.db_path) {
            Ok(c) => c,
            Err(e) => return internal(e).into_response(),
        };
        match db::get_vm(&conn, &name) {
            Ok(None) => return not_found(&name).into_response(),
            Err(e) => return internal(e).into_response(),
            Ok(Some(_)) => {}
        }
    } // conn dropped here

    let db_path = state.db_path.as_str().to_string();
    match vm::destroy(&db_path, &name).await {
        Ok(()) => Json(serde_json::json!({ "message": format!("VM '{name}' destroyed") }))
            .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `POST /api/vms/:name/exec` — Execute a command inside the VM.
async fn exec_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ExecRequest>,
) -> impl IntoResponse {
    // Sync: look up VM, then drop connection before await.
    let vsock_socket = {
        let conn = match db::open(&state.db_path) {
            Ok(c) => c,
            Err(e) => return internal(e).into_response(),
        };
        match db::get_vm(&conn, &name) {
            Ok(Some(v)) => std::path::PathBuf::from(v.ch_vsock_socket),
            Ok(None) => return not_found(&name).into_response(),
            Err(e) => return internal(e).into_response(),
        }
    }; // conn dropped

    let response = match agent::send_request(
        &vsock_socket,
        AgentRequest::Exec { command: req.command, args: req.args },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e).into_response(),
    };

    match response {
        AgentResponse::Ok {
            data: Some(ResponseData::Exec { exit_code, stdout, stderr }),
            ..
        } => Json(ExecResponse { exit_code, stdout, stderr }).into_response(),
        AgentResponse::Error { message } => internal(message).into_response(),
        other => internal(format!("unexpected response: {other:?}")).into_response(),
    }
}

/// `GET /api/vms/:name/status` — Agent status.
async fn vm_status(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Sync: look up VM, then drop connection before await.
    let vsock_socket = {
        let conn = match db::open(&state.db_path) {
            Ok(c) => c,
            Err(e) => return internal(e).into_response(),
        };
        match db::get_vm(&conn, &name) {
            Ok(Some(v)) => std::path::PathBuf::from(v.ch_vsock_socket),
            Ok(None) => return not_found(&name).into_response(),
            Err(e) => return internal(e).into_response(),
        }
    }; // conn dropped

    match agent::send_request(&vsock_socket, AgentRequest::ReportStatus).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `GET /api/vms/:name/logs` — Serial console log.
async fn vm_logs(
    State(_state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let log_path = storage::serial_log_path(&name);
    match std::fs::read_to_string(&log_path) {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            content,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: format!("no logs found for VM '{name}'") }),
        )
            .into_response(),
    }
}
