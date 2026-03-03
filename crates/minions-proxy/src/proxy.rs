//! HTTP reverse proxy handler.
//!
//! Receives every request (TLS already terminated by rustls),
//! extracts the subdomain, looks up the VM, checks auth, and forwards.
//!
//! WebSocket upgrade requests (`Upgrade: websocket`) are detected and tunnelled:
//! a raw TCP connection is opened to the VM, the HTTP upgrade handshake is
//! forwarded, and once both sides return 101 the two streams are spliced
//! bidirectionally with zero protocol awareness.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use hyper_util::rt::TokioIo;
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::auth::{
    LoginRateLimiter, Sessions, clear_cookie, extract_token, locked_out_page, login_page,
    redirect_to_login, safe_next, set_cookie,
};
use crate::connection_limit::{ConnectionLimiter, connection_limit_response};
use crate::db;
use crate::rate_limit::{RateLimiter, rate_limit_response};

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
    /// Request rate limiter per IP.
    pub rate_limiter: Arc<RateLimiter>,
    /// Login rate limiter for brute force protection.
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    /// Connection limiter.
    pub connection_limiter: Arc<ConnectionLimiter>,
}

// ── Main handler ──────────────────────────────────────────────────────────────

pub async fn handle(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    req: Request,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Strip port suffix from Host if present.
    let host = host.split(':').next().unwrap_or("");

    // Extract client IP (respecting X-Forwarded-For, X-Real-IP headers).
    let client_ip = crate::rate_limit::extract_client_ip(&req)
        .unwrap_or_else(|| addr.ip());

    // ── Connection limiting check ─────────────────────────────────────────────
    let _conn_guard = match state.connection_limiter.acquire(client_ip) {
        Some(guard) => guard,
        None => {
            warn!(ip = %client_ip, "connection limit exceeded");
            return connection_limit_response();
        }
    };

    // ── Rate limiting check ───────────────────────────────────────────────────
    if !state.rate_limiter.check(client_ip) {
        warn!(ip = %client_ip, "rate limit exceeded");
        return rate_limit_response(state.rate_limiter.config.window_secs);
    }

    // ── Internal /__minions/ routes ───────────────────────────────────────────
    let path = req.uri().path().to_string();
    if path.starts_with("/__minions/") {
        return handle_internal(req, client_ip, &state).await;
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

    // ── WebSocket upgrade ─────────────────────────────────────────────────────
    if is_websocket_upgrade(&req) {
        debug!(vm = %vm.name, port = vm.proxy_port, "WebSocket upgrade — tunnelling");
        return ws_upgrade(req, &vm.ip, vm.proxy_port, host).await;
    }

    // ── Normal HTTP forward ───────────────────────────────────────────────────
    let origin = format!("http://{}:{}", vm.ip, vm.proxy_port);
    forward(req, &origin, host, &state.http_client).await
}

// ── WebSocket tunnel ──────────────────────────────────────────────────────────

/// Returns true when the request carries `Upgrade: websocket`.
fn is_websocket_upgrade(req: &Request) -> bool {
    req.headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Tunnel a WebSocket upgrade between the client and a VM.
///
/// 1. Connect to the VM over raw TCP.
/// 2. Forward the client's HTTP upgrade request verbatim.
/// 3. Read the VM's 101 response and parse its headers.
/// 4. Return a matching 101 to the client.
/// 5. Spawn a background task that awaits hyper's `on_upgrade` and then
///    bidirectionally copies bytes between the two raw streams.
async fn ws_upgrade(req: Request, vm_ip: &str, vm_port: u16, original_host: &str) -> Response {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = format!("{}:{}", vm_ip, vm_port);

    // ── 1. Connect to VM ──────────────────────────────────────────────────────
    let mut vm_stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("WS: TCP connect to {} failed: {}", addr, e);
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Could not reach the VM — is the web server running?",
            );
        }
    };

    // ── 2. Decompose the request, extracting the OnUpgrade handle ─────────────
    let (mut parts, _body) = req.into_parts();

    let on_upgrade = match parts.extensions.remove::<hyper::upgrade::OnUpgrade>() {
        Some(u) => u,
        None => {
            warn!("WS: no OnUpgrade in request extensions");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "Connection upgrade not supported",
            );
        }
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // ── 3. Build the raw HTTP/1.1 upgrade request for the VM ──────────────────
    let mut raw = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path_and_query, original_host);

    for (name, value) in &parts.headers {
        let n = name.as_str();
        // Host already set above.
        if n.eq_ignore_ascii_case("host") {
            continue;
        }
        if let Ok(v) = value.to_str() {
            raw.push_str(n);
            raw.push_str(": ");
            raw.push_str(v);
            raw.push_str("\r\n");
        }
    }
    raw.push_str("X-Forwarded-Host: ");
    raw.push_str(original_host);
    raw.push_str("\r\nX-Forwarded-Proto: https\r\n\r\n");

    // Send to VM.
    if let Err(e) = vm_stream.write_all(raw.as_bytes()).await {
        warn!("WS: write upgrade request to {} failed: {}", addr, e);
        return error_response(StatusCode::BAD_GATEWAY, "Failed to send upgrade to VM");
    }

    // ── 4. Read the VM's HTTP response headers ────────────────────────────────
    let mut buf = Vec::with_capacity(4096);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
    let mut tmp = [0u8; 1024];
    loop {
        match tokio::time::timeout_at(deadline, vm_stream.read(&mut tmp)).await {
            Ok(Ok(0)) => {
                warn!("WS: VM closed during upgrade handshake");
                return error_response(StatusCode::BAD_GATEWAY, "VM closed during upgrade");
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 8192 {
                    warn!("WS: upgrade response too large from {}", addr);
                    return error_response(StatusCode::BAD_GATEWAY, "Upgrade response too large");
                }
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Ok(Err(e)) => {
                warn!("WS: read error during upgrade from {}: {}", addr, e);
                return error_response(StatusCode::BAD_GATEWAY, "Read error during upgrade");
            }
            Err(_) => {
                warn!("WS: timeout waiting for upgrade response from {}", addr);
                return error_response(StatusCode::GATEWAY_TIMEOUT, "VM upgrade response timeout");
            }
        }
    }

    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap();
    // Any bytes after the headers are already WebSocket frame data — keep them.
    let leftover = buf[header_end + 4..].to_vec();
    let header_bytes = &buf[..header_end];
    let header_str = String::from_utf8_lossy(header_bytes);

    // ── 5. Parse VM response — must be 101 ────────────────────────────────────
    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or("");
    if !status_line.contains("101") {
        warn!("WS: VM rejected upgrade: {}", status_line);
        return error_response(
            StatusCode::BAD_GATEWAY,
            &format!("VM rejected WebSocket upgrade: {status_line}"),
        );
    }

    // Parse response headers to mirror back to the client.
    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket");

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim();
            // Forward WebSocket-specific headers; skip connection/upgrade (we set them above).
            match key.as_str() {
                "connection" | "upgrade" => {}
                _ => {
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(k.trim().as_bytes()),
                        HeaderValue::from_str(val),
                    ) {
                        response = response.header(hn, hv);
                    }
                }
            }
        }
    }

    // ── 6. Spawn the bidirectional splice ─────────────────────────────────────
    let addr_owned = addr.clone();
    tokio::spawn(async move {
        // Wait for hyper to hand us the raw client IO.
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                warn!("WS: client upgrade failed: {}", e);
                return;
            }
        };

        let mut client_io = TokioIo::new(upgraded);

        // If the VM sent any leftover bytes after the header boundary, write
        // them into the client before starting the bidirectional copy.
        if !leftover.is_empty() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut client_io, &leftover).await {
                warn!("WS: failed to flush leftover to client: {}", e);
                return;
            }
        }

        // Splice until one side closes.
        match tokio::io::copy_bidirectional(&mut client_io, &mut vm_stream).await {
            Ok((c2v, v2c)) => {
                debug!(
                    "WS: tunnel to {} closed (client→vm: {} B, vm→client: {} B)",
                    addr_owned, c2v, v2c
                );
            }
            Err(e) => {
                // Connection resets are expected when either side closes.
                debug!("WS: tunnel to {} ended: {}", addr_owned, e);
            }
        }
    });

    // ── 7. Return the 101 to the client ───────────────────────────────────────
    response.body(Body::empty()).unwrap_or_else(|_| {
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Failed to build upgrade response")
    })
}

// ── Internal routes ───────────────────────────────────────────────────────────

async fn handle_internal(req: Request, client_ip: std::net::IpAddr, state: &AppState) -> Response {
    let path = req.uri().path();
    match (req.method().clone(), path) {
        (Method::GET, "/__minions/login") => {
            // Check if IP is locked out before showing login page
            if let Err(retry_after) = state.login_rate_limiter.check(client_ip) {
                warn!(ip = %client_ip, "login page blocked due to rate limit");
                return locked_out_page(retry_after);
            }

            let next_raw = query_param(req.uri(), "next").unwrap_or_else(|| "/".to_string());
            // Validate before embedding in the login form to prevent open redirect.
            let next = safe_next(&next_raw).to_string();
            login_page(&next, false)
        }
        (Method::POST, "/__minions/login") => handle_login_post(req, client_ip, state).await,
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

async fn handle_login_post(
    req: Request,
    client_ip: std::net::IpAddr,
    state: &AppState,
) -> Response {
    // Check rate limit before processing login
    if let Err(retry_after) = state.login_rate_limiter.check(client_ip) {
        warn!(ip = %client_ip, "login blocked due to rate limit");
        return locked_out_page(retry_after);
    }

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
        // Record failed login attempt
        state.login_rate_limiter.record_failure(client_ip);
        return login_page(next, true);
    }

    // Record successful login (clears failure streak)
    state.login_rate_limiter.record_success(client_ip);

    let token = state.sessions.create();
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, next)
        .header(header::SET_COOKIE, set_cookie(&token))
        .body(Body::empty())
        .unwrap()
}

// ── Request forwarding ────────────────────────────────────────────────────────

/// Hop-by-hop headers that must not be forwarded in normal HTTP requests.
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

    // Add security headers.
    resp = add_security_headers(resp);

    // Stream the response body back to the client.
    let body = Body::from_stream(upstream_resp.bytes_stream());
    resp.body(body)
        .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response error"))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Add security headers to a response builder.
pub fn add_security_headers(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    builder
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "strict-origin-when-cross-origin")
        .header(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
}

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
    add_security_headers(
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8"),
    )
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
        add_security_headers(
            Response::builder().status(StatusCode::NOT_FOUND)
        )
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

    add_security_headers(
        Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, location),
    )
    .body(Body::from("Redirecting to HTTPS"))
    .unwrap()
}
