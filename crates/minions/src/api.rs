//! HTTP API routes (axum).
//!
//! All responses are JSON. Errors use standard HTTP status codes.
//! Each handler opens its own SQLite connection (WAL mode → safe concurrent reads).

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::{auth, db, metrics, server::AppState, vm};
use minions_proto::{Request as AgentRequest, Response as AgentResponse, ResponseData};

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router(state: AppState) -> Router {
    // Clone auth config for middleware
    let auth_config = state.auth.clone();

    let mut router = Router::new()
        .route("/api/vms", post(create_vm))
        .route("/api/vms", get(list_vms))
        .route("/api/vms/{name}", get(get_vm))
        .route("/api/vms/{name}", delete(destroy_vm))
        .route("/api/vms/{name}/start", post(start_vm))
        .route("/api/vms/{name}/stop", post(stop_vm))
        .route("/api/vms/{name}/restart", post(restart_vm))
        .route("/api/vms/{name}/rename", post(rename_vm))
        .route("/api/vms/{name}/resize", post(resize_vm))
        .route("/api/vms/{name}/copy", post(copy_vm))
        .route("/api/vms/{name}/exec", post(exec_vm))
        .route("/api/vms/{name}/status", get(vm_status))
        .route("/api/vms/{name}/logs", get(vm_logs))
        .route("/api/vms/{name}/expose", post(expose_vm))
        .route("/api/vms/{name}/set-public", post(set_vm_public))
        .route("/api/vms/{name}/set-private", post(set_vm_private))
        // Custom domain routes
        .route("/api/vms/{name}/domains", post(add_custom_domain))
        .route("/api/vms/{name}/domains", get(list_custom_domains))
        .route(
            "/api/vms/{name}/domains/{domain}",
            delete(remove_custom_domain),
        )
        // Snapshot routes
        .route("/api/vms/{name}/snapshots", post(create_snapshot))
        .route("/api/vms/{name}/snapshots", get(list_snapshots))
        .route(
            "/api/vms/{name}/snapshots/{snap}/restore",
            post(restore_snapshot),
        )
        .route("/api/vms/{name}/snapshots/{snap}", delete(delete_snapshot))
        // Resource / billing routes
        .route("/api/billing/plans", get(billing_plans))
        .route("/api/billing/subscription", get(billing_subscription))
        .route("/api/billing/plan", post(billing_set_plan))
        // Per-VM metrics (authenticated)
        .route("/api/vms/{name}/metrics", get(vm_metrics))
        // Add authentication middleware (checks Bearer token if MINIONS_API_KEY is set)
        .layer(middleware::from_fn_with_state(
            auth_config,
            auth::require_auth,
        ));

    // CORS: only enable if explicit origins are configured via MINIONS_CORS_ORIGINS.
    // Default is no CORS to prevent cross-site API access.
    if !state.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = state
            .cors_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        router = router.layer(
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        );
    }

    // `/metrics` is intentionally unauthenticated — standard Prometheus practice.
    // It contains only operational data (counts, percentages), not user content.
    let public = Router::new().route("/metrics", get(prometheus_metrics));

    router
        .merge(public)
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
    /// SSH gateway user who will own this VM.
    /// Supplied by the SSH gateway; absent for direct admin API calls.
    pub owner_id: Option<String>,
}

fn default_cpus() -> u32 {
    2
}
fn default_memory() -> u32 {
    1024
}

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
    pub proxy_port: u16,
    pub proxy_public: bool,
    /// Owner of this VM (SSH gateway user id), or null for admin-created VMs.
    pub owner_id: Option<String>,
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
            proxy_port: v.proxy_port,
            proxy_public: v.proxy_public,
            owner_id: v.owner_id,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RenameRequest {
    pub new_name: String,
}

#[derive(Debug, Deserialize)]
pub struct ResizeRequest {
    pub vcpus: Option<u32>,
    pub memory_mb: Option<u32>,
    pub disk_gb: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CopyRequest {
    pub new_name: String,
    /// Owner for the new copy. Supplied by the SSH gateway; absent for admin copies.
    pub owner_id: Option<String>,
}

/// Query parameters for `GET /api/vms`.
#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// Filter VMs by owner. When set, only VMs with this owner_id are returned.
    pub owner_id: Option<String>,
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

// ── Name validation ───────────────────────────────────────────────────────────

/// Validate that a VM name from a URL path parameter is safe to use in
/// filesystem operations. This mirrors the `validate_name` check in `vm.rs`
/// and prevents path traversal attacks (e.g. `../../../etc`).
fn validate_name_param(name: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if name.is_empty()
        || name.len() > 11
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid VM name '{name}'"),
            }),
        ))
    } else {
        Ok(())
    }
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: e.to_string(),
        }),
    )
}

fn not_found(name: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("VM '{name}' not found"),
        }),
    )
}

fn bad_request(msg: impl std::fmt::Display) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
        }),
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
    let owner_id = req.owner_id.clone();

    match vm::create(
        &db_path,
        &req.name,
        req.cpus,
        req.memory_mb,
        ssh_pubkey,
        owner_id,
    )
    .await
    {
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

/// `GET /api/vms` — List VMs.
///
/// Optional query parameter: `?owner_id=<user_id>` — filter by owner.
/// When absent, all VMs are returned (admin view).
async fn list_vms(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    let vms_result = if let Some(ref owner_id) = query.owner_id {
        db::list_vms_by_owner(&conn, owner_id)
    } else {
        db::list_vms(&conn)
    };

    match vms_result {
        Ok(vms) => {
            // Correct stale "running" status for dead processes.
            let mut vms_out: Vec<_> = vms.into_iter().map(VmResponse::from).collect();
            // (Status reconciliation happens in vm::list; here we return raw DB values.)
            let _ = vms_out.iter_mut(); // no-op, reconciliation is in vm::list
            Json(vms_out).into_response()
        }
        Err(e) => internal(e).into_response(),
    }
}

/// `GET /api/vms/:name` — Get VM details.
async fn get_vm(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
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
async fn destroy_vm(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
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
        Ok(()) => {
            Json(serde_json::json!({ "message": format!("VM '{name}' destroyed") })).into_response()
        }
        Err(e) => internal(e).into_response(),
    }
}

/// `POST /api/vms/:name/stop` — Halt a VM (CH process + TAP), keep rootfs + DB record.
async fn stop_vm(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    info!(name = %name, "stop VM");
    let db_path = state.db_path.as_str().to_string();
    match vm::stop(&db_path, &name).await {
        Ok(v) => Json(VmResponse::from(v)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            // Only 404 when the VM genuinely doesn't exist in the DB.
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("already stopped") {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/start` — Start a stopped VM using its existing rootfs.
async fn start_vm(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    info!(name = %name, "start VM");
    let db_path = state.db_path.as_str().to_string();
    match vm::start(&db_path, &name).await {
        Ok(v) => Json(VmResponse::from(v)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("not stopped") {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/restart` — Reboot a running VM via ACPI signal.
async fn restart_vm(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    info!(name = %name, "restart VM");
    let db_path = state.db_path.as_str().to_string();
    match vm::restart(&db_path, &name).await {
        Ok(v) => Json(VmResponse::from(v)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            // Only 404 when the VM genuinely doesn't exist in the DB.
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("not running") {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/resize` — Resize a stopped VM's resources (CPU, memory, disk).
async fn resize_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<ResizeRequest>,
) -> impl IntoResponse {
    info!(name = %name, vcpus = ?req.vcpus, memory_mb = ?req.memory_mb, disk_gb = ?req.disk_gb, "resize VM");
    let db_path = state.db_path.as_str().to_string();
    match vm::resize(&db_path, &name, req.vcpus, req.memory_mb, req.disk_gb).await {
        Ok(v) => Json(VmResponse::from(v)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("must be stopped")
                || msg.contains("at least one")
                || msg.contains("must be between")
                || msg.contains("cannot shrink")
                || msg.contains("quota")
            {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/rename` — Rename a VM (running or stopped).
async fn rename_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RenameRequest>,
) -> impl IntoResponse {
    info!(name = %name, new_name = %req.new_name, "rename VM");
    let db_path = state.db_path.as_str().to_string();
    match vm::rename(&db_path, &name, &req.new_name).await {
        Ok(()) => Json(serde_json::json!({
            "message": format!("VM '{}' renamed to '{}'", name, req.new_name)
        }))
        .into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("already exists")
                || msg.contains("must only contain")
                || msg.contains("characters or fewer")
            {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/copy` — Copy a VM (running or stopped) to a new VM.
async fn copy_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<CopyRequest>,
) -> impl IntoResponse {
    info!(name = %name, new_name = %req.new_name, "copy VM");
    let db_path = state.db_path.as_str().to_string();
    let ssh_pubkey = state.ssh_pubkey.as_deref().map(|s| s.to_string());
    let owner_id = req.owner_id.clone();
    match vm::copy(&db_path, &name, &req.new_name, ssh_pubkey, owner_id).await {
        Ok(v) => (StatusCode::CREATED, Json(VmResponse::from(v))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("VM '") && msg.contains("' not found") {
                not_found(&name).into_response()
            } else if msg.contains("already exists")
                || msg.contains("must only contain")
                || msg.contains("characters or fewer")
            {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
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

    let response = match minions_node::agent::send_request(
        &vsock_socket,
        AgentRequest::Exec {
            command: req.command,
            args: req.args,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return internal(e).into_response(),
    };

    match response {
        AgentResponse::Ok {
            data:
                Some(ResponseData::Exec {
                    exit_code,
                    stdout,
                    stderr,
                }),
            ..
        } => Json(ExecResponse {
            exit_code,
            stdout,
            stderr,
        })
        .into_response(),
        AgentResponse::Error { message } => internal(message).into_response(),
        other => internal(format!("unexpected response: {other:?}")).into_response(),
    }
}

/// `GET /api/vms/:name/status` — Agent status.
async fn vm_status(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
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

    match minions_node::agent::send_request(&vsock_socket, AgentRequest::ReportStatus).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `GET /api/vms/:name/logs` — Serial console log.
async fn vm_logs(State(_state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    // Validate the name to prevent path traversal before filesystem access.
    if let Err(e) = validate_name_param(&name) {
        return e.into_response();
    }
    let log_path = minions_node::storage::serial_log_path(&name);
    match std::fs::read_to_string(&log_path) {
        Ok(content) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            content,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("no logs found for VM '{name}'"),
            }),
        )
            .into_response(),
    }
}

// ── Proxy configuration ───────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct ExposeParams {
    port: u16,
}

/// `POST /api/vms/:name/expose` — Set the proxy port.
async fn expose_vm(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(params): Json<ExposeParams>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    if !(1..=65535).contains(&params.port) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "port must be between 1 and 65535".into(),
            }),
        )
            .into_response();
    }
    match db::set_proxy_port(&conn, &name, params.port) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "name": name, "proxy_port": params.port })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("VM '{name}' not found"),
            }),
        )
            .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `POST /api/vms/:name/set-public` — Make VM publicly accessible without auth.
async fn set_vm_public(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    match db::set_proxy_public(&conn, &name, true) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "name": name, "proxy_public": true })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("VM '{name}' not found"),
            }),
        )
            .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `POST /api/vms/:name/set-private` — Require auth to access VM proxy.
async fn set_vm_private(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    match db::set_proxy_public(&conn, &name, false) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "name": name, "proxy_public": false })),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("VM '{name}' not found"),
            }),
        )
            .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

// ── Resource / plan types & handlers ──────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PlanResponse {
    id: String,
    name: String,
    max_vms: u32,
    max_vcpus: u32,
    max_memory_mb: u32,
    max_disk_gb: u32,
    max_snapshots: u32,
    price_cents: u32,
}

impl From<db::Plan> for PlanResponse {
    fn from(p: db::Plan) -> Self {
        PlanResponse {
            id: p.id,
            name: p.name,
            max_vms: p.max_vms,
            max_vcpus: p.max_vcpus,
            max_memory_mb: p.max_memory_mb,
            max_disk_gb: p.max_disk_gb,
            max_snapshots: p.max_snapshots,
            price_cents: p.price_cents,
        }
    }
}

#[derive(Debug, Serialize)]
struct UsageResponse {
    vm_count: u32,
    total_vcpus: u32,
    total_memory_mb: u32,
    snapshot_count: u32,
}

#[derive(Debug, Serialize)]
struct SubscriptionResponse {
    plan: PlanResponse,
    status: String,
    usage: UsageResponse,
}

#[derive(Debug, Deserialize)]
struct SetPlanRequest {
    owner_id: String,
    plan_id: String,
}

/// `GET /api/billing/plans` — List all available plans.
async fn billing_plans(State(state): State<AppState>) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    match db::list_plans(&conn) {
        Ok(plans) => Json(
            plans
                .into_iter()
                .map(PlanResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `GET /api/billing/subscription?owner_id=<id>` — Current plan + live usage.
async fn billing_subscription(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    let owner_id = match &query.owner_id {
        Some(id) => id.clone(),
        None => return bad_request("owner_id query parameter required").into_response(),
    };
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    let (sub, plan) = match db::get_user_plan(&conn, &owner_id) {
        Ok(pair) => pair,
        Err(e) => return internal(e).into_response(),
    };
    let usage = match db::get_user_usage(&conn, &owner_id) {
        Ok(u) => u,
        Err(e) => return internal(e).into_response(),
    };
    Json(SubscriptionResponse {
        plan: PlanResponse::from(plan),
        status: sub.status,
        usage: UsageResponse {
            vm_count: usage.vm_count,
            total_vcpus: usage.total_vcpus,
            total_memory_mb: usage.total_memory_mb,
            snapshot_count: usage.snapshot_count,
        },
    })
    .into_response()
}

/// `POST /api/billing/plan` — Manually set a user's plan (admin use / future billing hook).
async fn billing_set_plan(
    State(state): State<AppState>,
    Json(req): Json<SetPlanRequest>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };
    // Verify plan exists.
    match db::get_plan(&conn, &req.plan_id) {
        Ok(None) => return bad_request(format!("unknown plan '{}'", req.plan_id)).into_response(),
        Err(e) => return internal(e).into_response(),
        Ok(Some(_)) => {}
    }
    // Ensure user has a subscription row first.
    if db::get_subscription(&conn, &req.owner_id)
        .ok()
        .flatten()
        .is_none()
    {
        let _ = db::create_subscription(&conn, &req.owner_id, &req.plan_id);
    } else {
        match db::set_user_plan(&conn, &req.owner_id, &req.plan_id) {
            Ok(_) => {}
            Err(e) => return internal(e).into_response(),
        }
    }
    Json(serde_json::json!({
        "owner_id": req.owner_id,
        "plan_id": req.plan_id,
        "message": format!("plan updated to '{}'", req.plan_id)
    }))
    .into_response()
}

// ── Custom Domain types & handlers ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddCustomDomainRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
struct CustomDomainResponse {
    pub id: String,
    pub vm_name: String,
    pub domain: String,
    pub verified: bool,
    pub created_at: String,
}

impl From<db::CustomDomain> for CustomDomainResponse {
    fn from(d: db::CustomDomain) -> Self {
        CustomDomainResponse {
            id: d.id,
            vm_name: d.vm_name,
            domain: d.domain,
            verified: d.verified,
            created_at: d.created_at,
        }
    }
}

/// Validate custom domain format and check it's not a subdomain of base_domain.
fn validate_custom_domain(domain: &str, base_domain: Option<&str>) -> Result<(), String> {
    // Basic hostname validation
    if domain.is_empty() || domain.len() > 253 {
        return Err("domain must be 1-253 characters".to_string());
    }

    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err("invalid domain format".to_string());
    }

    // Labels must be alphanumeric + hyphens, not starting/ending with hyphen
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("domain labels must be 1-63 characters".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("domain must contain only letters, numbers, dots, and hyphens".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain labels cannot start or end with hyphen".to_string());
        }
    }

    // Reject if it's a subdomain of base_domain (those use wildcard cert)
    if let Some(base) = base_domain {
        let suffix = format!(".{}", base);
        if domain == base || domain.ends_with(&suffix) {
            return Err(format!(
                "cannot add subdomains of {} as custom domains (use {}.{} directly)",
                base, "<vmname>", base
            ));
        }
    }

    Ok(())
}

/// `POST /api/vms/:name/domains` — Add a custom domain.
async fn add_custom_domain(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<AddCustomDomainRequest>,
) -> impl IntoResponse {
    info!(vm = %name, domain = %req.domain, "add custom domain");

    // Validate domain format
    let base_domain_str = state.domain.as_ref().map(|s| s.as_str());
    if let Err(e) = validate_custom_domain(&req.domain, base_domain_str) {
        return bad_request(e).into_response();
    }

    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    // Check VM exists
    match db::get_vm(&conn, &name) {
        Ok(None) => return not_found(&name).into_response(),
        Err(e) => return internal(e).into_response(),
        Ok(Some(_)) => {}
    }

    // Check domain not already registered
    match db::get_custom_domain_by_name(&conn, &req.domain) {
        Ok(Some(existing)) => {
            return bad_request(format!(
                "domain '{}' is already registered to VM '{}'",
                req.domain, existing.vm_name
            ))
            .into_response();
        }
        Err(e) => return internal(e).into_response(),
        Ok(None) => {}
    }

    // DNS verification (if base_domain and public_ip are configured)
    if let Some(base) = base_domain_str {
        let public_ip = state.public_ip.as_ref().map(|s| s.as_str());
        match crate::dns::verify_domain_dns(&req.domain, &name, base, public_ip).await {
            Ok(true) => {
                info!(domain = %req.domain, "DNS verification passed");
            }
            Ok(false) => {
                return bad_request(format!(
                    "DNS verification failed: '{}' must have a CNAME pointing to '{}.{}' or an A record pointing to the host IP",
                    req.domain, name, base
                )).into_response();
            }
            Err(e) => {
                warn!(domain = %req.domain, error = %e, "DNS verification error");
                return bad_request(format!(
                    "DNS lookup failed: {} (check that the domain exists and is accessible)",
                    e
                ))
                .into_response();
            }
        }
    }

    // Add to DB (initially unverified — the proxy will provision certs and mark verified)
    let id = match db::add_custom_domain(&conn, &name, &req.domain) {
        Ok(id) => id,
        Err(e) => return internal(e).into_response(),
    };

    // The proxy's background ACME task will provision the certificate
    // and mark the domain as verified once provisioning succeeds.
    let domain_record = db::CustomDomain {
        id,
        vm_name: name.clone(),
        domain: req.domain.clone(),
        verified: false, // Will be set to true by proxy after cert provisioning
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    (
        StatusCode::CREATED,
        Json(CustomDomainResponse::from(domain_record)),
    )
        .into_response()
}

/// `GET /api/vms/:name/domains` — List custom domains for a VM.
async fn list_custom_domains(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    // Check VM exists
    match db::get_vm(&conn, &name) {
        Ok(None) => return not_found(&name).into_response(),
        Err(e) => return internal(e).into_response(),
        Ok(Some(_)) => {}
    }

    match db::list_custom_domains(&conn, &name) {
        Ok(domains) => Json(
            domains
                .into_iter()
                .map(CustomDomainResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

/// `DELETE /api/vms/:name/domains/:domain` — Remove a custom domain.
async fn remove_custom_domain(
    State(state): State<AppState>,
    Path((name, domain)): Path<(String, String)>,
) -> impl IntoResponse {
    info!(vm = %name, domain = %domain, "remove custom domain");

    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return internal(e).into_response(),
    };

    match db::remove_custom_domain(&conn, &name, &domain) {
        Ok(true) => Json(serde_json::json!({
            "message": format!("domain '{}' removed from VM '{}'", domain, name)
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("domain '{}' not found for VM '{}'", domain, name),
            }),
        )
            .into_response(),
        Err(e) => internal(e).into_response(),
    }
}

// ── Snapshot types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateSnapshotRequest {
    /// Snapshot name (optional — defaults to UTC timestamp).
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct SnapshotResponse {
    id: String,
    vm_name: String,
    name: String,
    size_bytes: Option<u64>,
    created_at: String,
}

impl From<db::Snapshot> for SnapshotResponse {
    fn from(s: db::Snapshot) -> Self {
        SnapshotResponse {
            id: s.id,
            vm_name: s.vm_name,
            name: s.name,
            size_bytes: s.size_bytes,
            created_at: s.created_at,
        }
    }
}

// ── Snapshot handlers ──────────────────────────────────────────────────────────

/// `POST /api/vms/:name/snapshots` — Create a snapshot.
async fn create_snapshot(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<CreateSnapshotRequest>,
) -> impl IntoResponse {
    info!(vm = %name, snap_name = ?req.name, "create snapshot");
    let db_path = state.db_path.as_str().to_string();
    match vm::snapshot(&db_path, &name, req.name).await {
        Ok(snap) => (StatusCode::CREATED, Json(SnapshotResponse::from(snap))).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                not_found(&name).into_response()
            } else if msg.contains("already exists")
                || msg.contains("limit reached")
                || msg.contains("must be")
                || msg.contains("still starting")
            {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `GET /api/vms/:name/snapshots` — List snapshots.
async fn list_snapshots(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let db_path = state.db_path.as_str().to_string();
    match vm::list_snapshots(&db_path, &name) {
        Ok(snaps) => Json(
            snaps
                .into_iter()
                .map(SnapshotResponse::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                not_found(&name).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `POST /api/vms/:name/snapshots/:snap/restore` — Restore from a snapshot.
async fn restore_snapshot(
    State(state): State<AppState>,
    Path((name, snap)): Path<(String, String)>,
) -> impl IntoResponse {
    info!(vm = %name, snap = %snap, "restore snapshot");
    let db_path = state.db_path.as_str().to_string();
    match vm::restore_snapshot(&db_path, &name, &snap).await {
        Ok(()) => Json(serde_json::json!({
            "message": format!("VM '{name}' restored from snapshot '{snap}'")
        }))
        .into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, Json(ErrorResponse { error: msg })).into_response()
            } else if msg.contains("must be stopped") {
                bad_request(msg).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

/// `DELETE /api/vms/:name/snapshots/:snap` — Delete a snapshot.
async fn delete_snapshot(
    State(state): State<AppState>,
    Path((name, snap)): Path<(String, String)>,
) -> impl IntoResponse {
    info!(vm = %name, snap = %snap, "delete snapshot");
    let db_path = state.db_path.as_str().to_string();
    match vm::delete_snapshot(&db_path, &name, &snap).await {
        Ok(()) => Json(serde_json::json!({
            "message": format!("snapshot '{snap}' deleted for VM '{name}'")
        }))
        .into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not found") {
                (StatusCode::NOT_FOUND, Json(ErrorResponse { error: msg })).into_response()
            } else {
                internal(msg).into_response()
            }
        }
    }
}

// ── Metrics handlers ───────────────────────────────────────────────────────────

/// `GET /metrics` — Prometheus text format scrape endpoint (unauthenticated).
async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = metrics::prometheus_text(&state.metrics);
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// `GET /api/vms/:name/metrics` — Per-VM metrics snapshot as JSON.
async fn vm_metrics(State(state): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    match state.metrics.get_vm(&name) {
        Some(m) => Json(m).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("no metrics collected yet for VM '{name}' (is it running?)"),
            }),
        )
            .into_response(),
    }
}
