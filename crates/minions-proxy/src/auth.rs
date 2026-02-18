//! Simple session-cookie auth for private VMs.
//!
//! The password is the value of `MINIONS_API_KEY` (same secret used by the
//! HTTP API). If no API key is set the proxy accepts all requests.
//!
//! Session tokens are stored in memory; they expire after 24 hours or when
//! the daemon restarts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use uuid::Uuid;

pub const COOKIE_NAME: &str = "minions_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

// ── Session store ─────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct Sessions(Arc<Mutex<HashMap<String, Instant>>>);

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a token is valid (exists and not expired).
    pub fn is_valid(&self, token: &str) -> bool {
        let mut map = self.0.lock().unwrap();
        match map.get(token) {
            Some(&created) if created.elapsed() < SESSION_TTL => true,
            Some(_) => {
                map.remove(token); // expired
                false
            }
            None => false,
        }
    }

    /// Issue a new session token.
    pub fn create(&self) -> String {
        let token = Uuid::new_v4().to_string();
        self.0.lock().unwrap().insert(token.clone(), Instant::now());
        token
    }

    /// Invalidate a token (logout).
    pub fn revoke(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

/// Extract the session token from the Cookie header.
pub fn extract_token(headers: &HeaderMap) -> Option<String> {
    let cookie_hdr = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_hdr
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            let (k, v) = part.split_once('=')?;
            if k.trim() == COOKIE_NAME { Some(v.trim().to_string()) } else { None }
        })
        .next()
}

/// Build a `Set-Cookie` header value that sets the session cookie.
pub fn set_cookie(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0")
}

// ── Login / logout pages ──────────────────────────────────────────────────────

/// Redirect the browser to the login page, preserving the original path.
pub fn redirect_to_login(original_path: &str) -> Response {
    let location = format!("/__minions/login?next={}", urlencode(original_path));
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .unwrap()
}

/// Render the login HTML form.
pub fn login_page(next: &str, error: bool) -> Response {
    let error_msg = if error {
        r#"<p class="err">Wrong password — try again.</p>"#
    } else {
        ""
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MINICLANKERS — Login</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;
           padding:2rem;width:100%;max-width:360px}}
    h1{{font-size:1.25rem;font-weight:600;margin-bottom:1.5rem;color:#f7fafc}}
    label{{display:block;font-size:.875rem;color:#a0aec0;margin-bottom:.4rem}}
    input{{width:100%;padding:.6rem .75rem;border:1px solid #4a5568;border-radius:6px;
           background:#2d3748;color:#f7fafc;font-size:1rem}}
    input:focus{{outline:2px solid #4299e1;border-color:#4299e1}}
    button{{margin-top:1rem;width:100%;padding:.65rem;border:none;border-radius:6px;
            background:#4299e1;color:#fff;font-size:1rem;cursor:pointer;font-weight:500}}
    button:hover{{background:#3182ce}}
    .err{{color:#fc8181;font-size:.875rem;margin-bottom:1rem}}
  </style>
</head>
<body>
  <div class="card">
    <h1>🔒 MINICLANKERS</h1>
    {error_msg}
    <form method="POST" action="/__minions/login">
      <input type="hidden" name="next" value="{next}">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>"#
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(html))
        .unwrap()
}

/// Minimal URL encoder (just enough for the `next` query param).
fn urlencode(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}
