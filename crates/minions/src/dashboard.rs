//! Web dashboard — server-rendered HTML via askama + htmx.
//!
//! Auth: admin API key entered on the login page is validated against
//! `MINIONS_API_KEY`. On success a session cookie is issued. All other
//! dashboard routes require a valid session cookie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use askama::Template;
use axum::{
    Form,
    Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{db, metrics::MetricsStore, server::AppState, vm};

// ── Session store ─────────────────────────────────────────────────────────────

const SESSION_COOKIE: &str = "minions_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone, Default)]
pub struct DashboardSessions(Arc<Mutex<HashMap<String, Instant>>>);

impl DashboardSessions {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    pub fn create(&self) -> String {
        let token = Uuid::new_v4().to_string();
        if let Ok(mut m) = self.0.lock() {
            m.insert(token.clone(), Instant::now());
        }
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        let Ok(mut m) = self.0.lock() else { return false };
        if let Some(ts) = m.get(token) {
            if ts.elapsed() < SESSION_TTL {
                return true;
            }
            m.remove(token);
        }
        false
    }

    pub fn delete(&self, token: &str) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(token);
        }
    }
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

fn get_session_token(headers: &HeaderMap) -> Option<String> {
    let cookie_str = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(val.to_string());
        }
    }
    None
}

fn set_session_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
    ))
    .unwrap()
}

fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .unwrap()
}

/// Check session cookie. Returns the token if valid, else `None`.
fn check_session(headers: &HeaderMap, sessions: &DashboardSessions) -> Option<String> {
    let token = get_session_token(headers)?;
    if sessions.validate(&token) { Some(token) } else { None }
}

// ── Template helper ───────────────────────────────────────────────────────────

/// Render an askama template into an HTML response.
fn render<T: Template>(t: T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Row types ─────────────────────────────────────────────────────────────────

struct VmRow {
    name: String,
    status: String,
    ip: String,
    vcpus: u32,
    memory_mb: u32,
    owner: String,
    cpu_percent: f64,
    cpu_percent_str: String,
}

struct SnapRow {
    name: String,
    created_at: String,
    size_mb: u64,
}

// ── Templates ─────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    vms: Vec<VmRow>,
}

#[derive(Template)]
#[template(path = "vms_fragment.html")]
struct VmsFragmentTemplate {
    vms: Vec<VmRow>,
}

#[derive(Template)]
#[template(path = "vm_detail.html")]
struct VmDetailTemplate {
    vm_name: String,
    vm_status: String,
    vm_ip: String,
    vm_vcpus: u32,
    vm_memory_mb: u32,
    vm_owner: String,
    has_metrics: bool,
    cpu_str: String,
    load_str: String,
    mem_used_mb: u64,
    mem_total_mb: u64,
    mem_pct_str: String,
    disk_used_gb: u64,
    disk_total_gb: u64,
    net_rx_str: String,
    net_tx_str: String,
    snapshots: Vec<SnapRow>,
    proxy_port: u16,
    proxy_public: bool,
    domain: String,
}

#[derive(Template)]
#[template(path = "metrics_fragment.html")]
struct MetricsFragmentTemplate {
    vm_name: String,
    has_metrics: bool,
    cpu_str: String,
    load_str: String,
    mem_used_mb: u64,
    mem_total_mb: u64,
    mem_pct_str: String,
    disk_used_gb: u64,
    disk_total_gb: u64,
    net_rx_str: String,
    net_tx_str: String,
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard/login", get(login_page).post(login_submit))
        .route("/dashboard/logout", get(logout))
        .route("/dashboard", get(dashboard))
        .route("/dashboard/vms-fragment", get(vms_fragment))
        .route("/dashboard/vms/{name}", get(vm_detail))
        .route("/dashboard/vms/{name}/metrics-fragment", get(metrics_fragment_handler))
        .route("/dashboard/vms/{name}/start", post(vm_start))
        .route("/dashboard/vms/{name}/restart", post(vm_restart))
        .route("/dashboard/vms/{name}/stop", post(vm_stop))
        .route("/dashboard/vms/{name}/snapshot", post(vm_snapshot))
        .route("/dashboard/vms/{name}/expose", post(vm_expose))
        .route("/dashboard/vms/{name}/set-public", post(vm_set_public))
        .route("/dashboard/vms/{name}/set-private", post(vm_set_private))
        .route("/dashboard/vms/{name}", delete(vm_destroy))
        .route(
            "/dashboard/vms/{name}/snapshots/{snap}/restore",
            post(vm_restore_snapshot),
        )
        .route(
            "/dashboard/vms/{name}/snapshots/{snap}",
            delete(vm_delete_snapshot),
        )
}

// ── Handlers — Auth ───────────────────────────────────────────────────────────

async fn login_page(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if check_session(&headers, &state.sessions).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    render(LoginTemplate { error: String::new() })
}

#[derive(Deserialize)]
struct LoginForm {
    api_key: String,
}

async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let expected = std::env::var("MINIONS_API_KEY").unwrap_or_default();
    if expected.is_empty() || !crate::auth::constant_time_eq(&form.api_key, &expected) {
        return render(LoginTemplate { error: "Invalid API key.".to_string() });
    }
    let token = state.sessions.create();
    let mut resp = Redirect::to("/dashboard").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, set_session_cookie(&token));
    resp
}

async fn logout(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if let Some(token) = get_session_token(&headers) {
        state.sessions.delete(&token);
    }
    let mut resp = Redirect::to("/dashboard/login").into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie());
    resp
}

// ── Handlers — Dashboard ──────────────────────────────────────────────────────

async fn dashboard(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return Redirect::to("/dashboard/login").into_response();
    }
    let vms = load_vm_rows(&state);
    render(DashboardTemplate { vms })
}

async fn vms_fragment(headers: HeaderMap, State(state): State<AppState>) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let vms = load_vm_rows(&state);
    render(VmsFragmentTemplate { vms })
}

async fn vm_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return Redirect::to("/dashboard/login").into_response();
    }
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let vm = match db::get_vm(&conn, &name) {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::NOT_FOUND, "VM not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let snapshots = db::list_snapshots(&conn, &name).unwrap_or_default().into_iter().map(|s| {
        let size_mb = snapshot_size_mb(&state.db_path, &name, &s.name);
        SnapRow { name: s.name, created_at: s.created_at, size_mb }
    }).collect();

    let (has_metrics, mf) = build_metrics_fields(&name, &state.metrics);

    render(VmDetailTemplate {
        vm_name: name.clone(),
        vm_status: vm.status.clone(),
        vm_ip: vm.ip.clone(),
        vm_vcpus: vm.vcpus,
        vm_memory_mb: vm.memory_mb,
        vm_owner: vm.owner_id.as_deref().unwrap_or("system").to_string(),
        has_metrics,
        cpu_str: mf.cpu_str,
        load_str: mf.load_str,
        mem_used_mb: mf.mem_used_mb,
        mem_total_mb: mf.mem_total_mb,
        mem_pct_str: mf.mem_pct_str,
        disk_used_gb: mf.disk_used_gb,
        disk_total_gb: mf.disk_total_gb,
        net_rx_str: mf.net_rx_str,
        net_tx_str: mf.net_tx_str,
        snapshots,
        proxy_port: vm.proxy_port,
        proxy_public: vm.proxy_public,
        domain: state.domain.as_deref().map_or(String::new(), |d| d.to_string()),
    })
}

async fn metrics_fragment_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (has_metrics, mf) = build_metrics_fields(&name, &state.metrics);
    render(MetricsFragmentTemplate {
        vm_name: name,
        has_metrics,
        cpu_str: mf.cpu_str,
        load_str: mf.load_str,
        mem_used_mb: mf.mem_used_mb,
        mem_total_mb: mf.mem_total_mb,
        mem_pct_str: mf.mem_pct_str,
        disk_used_gb: mf.disk_used_gb,
        disk_total_gb: mf.disk_total_gb,
        net_rx_str: mf.net_rx_str,
        net_tx_str: mf.net_tx_str,
    })
}

// ── Handlers — VM actions ─────────────────────────────────────────────────────

async fn vm_stop(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::stop(&db_path, &name).await {
        Ok(_) => Html("<span class='text-green-400 text-sm'>✓ VM stopped</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_start(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::start(&db_path, &name).await {
        Ok(_) => {
            // Redirect back to the VM detail page so the status badge refreshes.
            Redirect::to(&format!("/dashboard/vms/{name}")).into_response()
        }
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_restart(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::restart(&db_path, &name).await {
        Ok(_) => Html("<span class='text-green-400 text-sm'>✓ VM restarted</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_destroy(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::destroy(&db_path, &name).await {
        Ok(()) => Redirect::to("/dashboard").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_snapshot(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::snapshot(&db_path, &name, None).await {
        Ok(snap) => Html(format!(
            "<span class='text-green-400 text-sm'>✓ Snapshot '{}' created</span>",
            snap.name
        )).into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

#[derive(Deserialize)]
struct ExposeForm {
    port: u16,
}

async fn vm_expose(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Form(form): Form<ExposeForm>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    };
    if !(1..=65535).contains(&form.port) {
        return Html("<span class='text-red-400 text-sm'>✗ Port must be between 1 and 65535</span>").into_response();
    }
    match db::set_proxy_port(&conn, &name, form.port) {
        Ok(true) => Html(format!(
            "<span class='text-green-400 text-sm'>✓ Proxy port set to {}</span>",
            form.port
        )).into_response(),
        Ok(false) => Html("<span class='text-red-400 text-sm'>✗ VM not found</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_set_public(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    };
    match db::set_proxy_public(&conn, &name, true) {
        Ok(true) => {
            // Redirect back to the VM detail page so the access toggle updates.
            Redirect::to(&format!("/dashboard/vms/{name}")).into_response()
        }
        Ok(false) => Html("<span class='text-red-400 text-sm'>✗ VM not found</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_set_private(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => return Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    };
    match db::set_proxy_public(&conn, &name, false) {
        Ok(true) => {
            // Redirect back to the VM detail page so the access toggle updates.
            Redirect::to(&format!("/dashboard/vms/{name}")).into_response()
        }
        Ok(false) => Html("<span class='text-red-400 text-sm'>✗ VM not found</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_restore_snapshot(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((name, snap)): Path<(String, String)>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::restore_snapshot(&db_path, &name, &snap).await {
        Ok(()) => Html("<span class='text-green-400 text-sm'>✓ Restored successfully</span>").into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

async fn vm_delete_snapshot(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((name, snap)): Path<(String, String)>,
) -> Response {
    if check_session(&headers, &state.sessions).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db_path = state.db_path.as_ref().clone();
    match vm::delete_snapshot(&db_path, &name, &snap).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => Html(format!("<span class='text-red-400 text-sm'>✗ {e}</span>")).into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_vm_rows(state: &AppState) -> Vec<VmRow> {
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let vms = db::list_vms(&conn).unwrap_or_default();
    vms.into_iter().map(|vm| {
        let metrics = state.metrics.get_vm(&vm.name);
        let cpu_percent = metrics.as_ref().map(|m| m.cpu_usage_percent).unwrap_or(0.0);
        let cpu_percent_str = format!("{:.1}", cpu_percent);
        VmRow {
            name: vm.name,
            status: vm.status,
            ip: vm.ip,
            vcpus: vm.vcpus,
            memory_mb: vm.memory_mb,
            owner: vm.owner_id.as_deref().unwrap_or("system").to_string(),
            cpu_percent,
            cpu_percent_str,
        }
    }).collect()
}

struct MetricsFields {
    cpu_str: String,
    load_str: String,
    mem_used_mb: u64,
    mem_total_mb: u64,
    mem_pct_str: String,
    disk_used_gb: u64,
    disk_total_gb: u64,
    net_rx_str: String,
    net_tx_str: String,
}

fn build_metrics_fields(vm_name: &str, store: &MetricsStore) -> (bool, MetricsFields) {
    match store.get_vm(vm_name) {
        None => (false, MetricsFields {
            cpu_str: "0.0".into(), load_str: "0.00".into(),
            mem_used_mb: 0, mem_total_mb: 0, mem_pct_str: "0.0".into(),
            disk_used_gb: 0, disk_total_gb: 0,
            net_rx_str: "0.00".into(), net_tx_str: "0.00".into(),
        }),
        Some(m) => {
            let mem_pct = if m.memory_total_mb > 0 {
                m.memory_used_mb as f64 / m.memory_total_mb as f64 * 100.0
            } else { 0.0 };
            (true, MetricsFields {
                cpu_str: format!("{:.1}", m.cpu_usage_percent),
                load_str: format!("{:.2}", m.load_avg_1m),
                mem_used_mb: m.memory_used_mb,
                mem_total_mb: m.memory_total_mb,
                mem_pct_str: format!("{:.1}", mem_pct),
                disk_used_gb: m.disk_used_gb,
                disk_total_gb: m.disk_total_gb,
                net_rx_str: format!("{:.2}", m.network_rx_bytes as f64 / (1024.0 * 1024.0)),
                net_tx_str: format!("{:.2}", m.network_tx_bytes as f64 / (1024.0 * 1024.0)),
            })
        }
    }
}

/// Returns snapshot size in MiB by checking the rootfs file on disk.
fn snapshot_size_mb(db_path: &str, vm_name: &str, snap_name: &str) -> u64 {
    use crate::storage;
    let path = storage::snapshot_rootfs_path(vm_name, snap_name);
    std::fs::metadata(path).map(|m| m.len() / (1024 * 1024)).unwrap_or(0)
}
