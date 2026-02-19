//! HTTP reverse proxy handler.
//!
//! Receives every request from Cloudflare (already TLS-terminated),
//! extracts the subdomain, looks up the VM, checks auth, and forwards.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::auth::{
    Sessions, clear_cookie, extract_token, login_page, redirect_to_login, safe_next, set_cookie,
};
use crate::db;

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db_path: Arc<String>,
    /// Base domain, e.g. "miniclankers.com".
    pub domain: Arc<String>,
    /// Optional API key used as the proxy password.
    pub api_key: Option<Arc<String>>,
    /// Host public IP (for custom domain DNS verification).
    pub public_ip: Option<Arc<String>>,
    pub sessions: Sessions,
    pub http_client: reqwest::Client,
    /// ACME HTTP-01 challenge response map.
    pub acme_challenges: crate::ChallengeMap,
    /// ACME client (for provisioning custom domain certs).
    pub acme_client: Arc<crate::tls::AcmeClient>,
    /// SNI resolver (for loading custom domain certs after provision).
    pub sni_resolver: Arc<crate::tls::SniResolver>,
}

// ── Main handler ──────────────────────────────────────────────────────────────

pub async fn handle(State(state): State<AppState>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Strip port suffix from Host if present.
    let host = host.split(':').next().unwrap_or("");

    // ── Internal /__minions/ routes ───────────────────────────────────────────
    let path = req.uri().path().to_string();
    if path.starts_with("/__minions/") {
        return handle_internal(req, &state).await;
    }

    // ── Apex domain → forward to local dashboard ──────────────────────────────
    if host == state.domain.as_str() {
        debug!(host, "apex domain — forwarding to local dashboard");
        return forward(req, "http://127.0.0.1:3000", host, &state.http_client).await;
    }

    // ── Try custom domain lookup first ────────────────────────────────────────
    let conn = match db::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            warn!("db open error: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error");
        }
    };

    if let Ok(Some(vm)) = db::get_vm_by_custom_domain(&conn, host) {
        debug!(domain = host, vm = %vm.name, "custom domain match");
        return forward_to_vm(req, &vm, host, &state).await;
    }

    // ── Extract subdomain (*.miniclankers.com) ────────────────────────────────
    let subdomain = match extract_subdomain(host, &state.domain) {
        Some(s) => s,
        None => return error_response(StatusCode::NOT_FOUND, "Not found"),
    };

    debug!(subdomain, "proxy request (subdomain)");

    // ── VM lookup by subdomain ────────────────────────────────────────────────
    match db::get_vm_proxy(&conn, &subdomain) {
        Ok(Some(vm)) => forward_to_vm(req, &vm, host, &state).await,
        Ok(None) => error_response(StatusCode::NOT_FOUND, &format!("No VM named '{subdomain}'")),
        Err(e) => {
            warn!("db query error: {}", e);
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
        }
    }
}

// ── Forward to VM (auth + status check + proxy) ───────────────────────────────

async fn forward_to_vm(req: Request, vm: &db::VmProxy, host: &str, state: &AppState) -> Response {
    // Check VM status.
    if vm.status != "running" {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("VM '{}' is {}", vm.name, vm.status),
        );
    }

    // Auth check for private VMs.
    if !vm.proxy_public && state.api_key.is_some() {
        let token = extract_token(req.headers());
        let valid = token
            .as_deref()
            .map(|t| state.sessions.is_valid(t))
            .unwrap_or(false);
        if !valid {
            return redirect_to_login(req.uri().path());
        }
    }

    // Forward request to VM.
    let origin = format!("http://{}:{}", vm.ip, vm.proxy_port);
    forward(req, &origin, host, &state.http_client).await
}

// ── Internal routes ───────────────────────────────────────────────────────────

async fn handle_internal(req: Request, state: &AppState) -> Response {
    let path = req.uri().path();
    match (req.method().clone(), path) {
        (Method::GET, "/__minions/login") => {
            let next_raw = query_param(req.uri(), "next").unwrap_or_else(|| "/".to_string());
            // Validate before embedding in the login form to prevent open redirect.
            let next = safe_next(&next_raw).to_string();
            login_page(&next, false)
        }
        (Method::POST, "/__minions/login") => handle_login_post(req, state).await,
        (Method::GET, "/__minions/logout") => {
            if let Some(token) = extract_token(req.headers()) {
                state.sessions.revoke(&token);
            }
            Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "/")
                .header(header::SET_COOKIE, clear_cookie())
                .body(Body::empty())
                .unwrap()
        }
        _ => error_response(StatusCode::NOT_FOUND, "Not found"),
    }
}

async fn handle_login_post(req: Request, state: &AppState) -> Response {
    // Parse form body.
    let bytes = match axum::body::to_bytes(req.into_body(), 8192).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "Bad request"),
    };
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(&bytes).unwrap_or_default();

    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    // Sanitize the redirect target before using it to prevent open redirect.
    let next_raw = form.get("next").map(|s| s.as_str()).unwrap_or("/");
    let next = safe_next(next_raw);

    let expected = state.api_key.as_deref().map(|k| k.as_ref()).unwrap_or("");
    // Use constant-time comparison to prevent timing side-channel attacks.
    let password_ok = expected.is_empty() || password.as_bytes().ct_eq(expected.as_bytes()).into();
    if !password_ok {
        return login_page(next, true);
    }

    let token = state.sessions.create();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, next)
        .header(header::SET_COOKIE, set_cookie(&token))
        .body(Body::empty())
        .unwrap()
}

// ── Request forwarding ────────────────────────────────────────────────────────

/// Hop-by-hop headers that must not be forwarded.
static HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

async fn forward(
    req: Request,
    origin: &str,
    original_host: &str,
    client: &reqwest::Client,
) -> Response {
    let (parts, body) = req.into_parts();

    // Build the upstream URL.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{origin}{path_and_query}");

    // Collect the request body (32 MB limit).
    let body_bytes = match axum::body::to_bytes(body, 32 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"),
    };

    // Build the upstream request.
    let mut upstream = client
        .request(
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap(),
            &url,
        )
        .body(body_bytes);

    // Copy headers (excluding hop-by-hop).
    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (name, value) in &parts.headers {
        let n = name.as_str().to_lowercase();
        if !HOP_BY_HOP.contains(&n.as_str()) {
            if let (Ok(k), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                fwd_headers.insert(k, v);
            }
        }
    }

    // Inject forwarding headers.
    let _ = fwd_headers.insert(
        reqwest::header::HeaderName::from_static("x-forwarded-host"),
        reqwest::header::HeaderValue::from_str(original_host)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
    );
    let _ = fwd_headers.insert(
        reqwest::header::HeaderName::from_static("x-forwarded-proto"),
        reqwest::header::HeaderValue::from_static("https"),
    );

    upstream = upstream.headers(fwd_headers);

    // Send to upstream.
    let upstream_resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!("upstream error: {}", e);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Could not reach the VM — is the web server running?",
            );
        }
    };

    // Build the downstream response.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut resp = Response::builder().status(status);

    // Copy response headers (excluding hop-by-hop).
    for (name, value) in upstream_resp.headers() {
        let n = name.as_str().to_lowercase();
        if !HOP_BY_HOP.contains(&n.as_str()) {
            if let (Ok(k), Ok(v)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                resp = resp.header(k, v);
            }
        }
    }

    // Stream the response body back to the client.
    let body = Body::from_stream(upstream_resp.bytes_stream());
    resp.body(body)
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response error"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the subdomain from `host` given a `base_domain`.
/// e.g. host="myvm.miniclankers.com", domain="miniclankers.com" → Some("myvm")
pub fn extract_subdomain<'a>(host: &'a str, domain: &str) -> Option<String> {
    let suffix = format!(".{}", domain);
    if host == domain {
        return None; // apex domain, no subdomain
    }
    let sub = host.strip_suffix(&suffix)?;
    if sub.is_empty() || sub.contains('.') {
        return None; // nested subdomain or empty
    }
    Some(sub.to_string())
}

fn query_param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key {
            Some(v.replace('+', " "))
        } else {
            None
        }
    })
}

pub fn error_response(status: StatusCode, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{status}</title>
  <style>
    body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
    .box{{text-align:center}}
    h1{{font-size:4rem;font-weight:700;color:#fc8181;margin:0}}
    p{{color:#a0aec0;margin-top:.5rem}}
    a{{color:#4299e1;text-decoration:none}}
  </style>
</head>
<body>
  <div class="box">
    <h1>{code}</h1>
    <p>{message}</p>
    <p><a href="/">← home</a></p>
  </div>
</body>
</html>"#,
        status = status,
        code = status.as_u16(),
        message = message,
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

// ── ACME HTTP-01 Challenge Handler ────────────────────────────────────────────

use axum::extract::Path;

pub async fn acme_challenge(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    debug!(token, "ACME HTTP-01 challenge request");
    if let Some(key_auth) = state.acme_challenges.get(&token) {
        let response_text = key_auth.value().clone();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(response_text))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("challenge not found"))
            .unwrap()
    }
}

// ── HTTP → HTTPS Redirect ─────────────────────────────────────────────────────

pub async fn http_redirect(req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let location = format!("https://{}{}", host, path_and_query);

    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(Body::from("Redirecting to HTTPS"))
        .unwrap()
}
