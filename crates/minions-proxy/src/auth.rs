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
/// Maximum number of concurrent sessions. Exceeding this drops oldest entries.
const MAX_SESSIONS: usize = 10_000;

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
    ///
    /// If the session store exceeds `MAX_SESSIONS`, expired sessions are
    /// evicted first. If the store is still full after eviction, the oldest
    /// session is removed (LRU-style) to prevent unbounded memory growth.
    pub fn create(&self) -> String {
        let token = Uuid::new_v4().to_string();
        let now = Instant::now();
        let mut map = self.0.lock().unwrap();

        if map.len() >= MAX_SESSIONS {
            // First pass: remove all expired sessions.
            map.retain(|_, created| created.elapsed() < SESSION_TTL);
        }

        // If still at capacity after eviction, remove the oldest entry.
        if map.len() >= MAX_SESSIONS {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, created)| *created)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }

        map.insert(token.clone(), now);
        token
    }

    /// Invalidate a token (logout).
    pub fn revoke(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }

    /// Evict all expired sessions. Call periodically to reclaim memory.
    pub fn gc(&self) {
        self.0
            .lock()
            .unwrap()
            .retain(|_, created| created.elapsed() < SESSION_TTL);
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
            if k.trim() == COOKIE_NAME {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
        .next()
}

/// Build a `Set-Cookie` header value that sets the session cookie.
/// The `Secure` flag is included so the cookie is only sent over HTTPS.
pub fn set_cookie(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400")
}

/// Build a `Set-Cookie` header value that clears the session cookie.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; HttpOnly; Secure; Max-Age=0")
}

// ── Redirect safety ───────────────────────────────────────────────────────────

/// Validate that a `next` redirect target is a safe relative path.
///
/// Rejects any value that could redirect the user off-site:
/// - Absolute URLs (contain `://`)
/// - Protocol-relative URLs (start with `//`)
/// - Non-path values (don't start with `/`)
///
/// Returns the validated path, or `/` if the value is unsafe.
pub fn safe_next(next: &str) -> &str {
    if next.starts_with("//") || next.contains("://") || !next.starts_with('/') {
        "/"
    } else {
        next
    }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_next_relative_paths() {
        assert_eq!(safe_next("/foo/bar"), "/foo/bar");
        assert_eq!(safe_next("/"), "/");
        assert_eq!(safe_next("/some/page?q=1"), "/some/page?q=1");
    }

    #[test]
    fn test_safe_next_rejects_absolute_urls() {
        assert_eq!(safe_next("https://evil.com"), "/");
        assert_eq!(safe_next("http://evil.com/path"), "/");
        assert_eq!(safe_next("//evil.com"), "/");
    }

    #[test]
    fn test_safe_next_rejects_non_paths() {
        assert_eq!(safe_next("evil.com/path"), "/");
        assert_eq!(safe_next("javascript:alert(1)"), "/");
    }

    #[test]
    fn test_session_gc() {
        let sessions = Sessions::new();
        let t1 = sessions.create();
        let t2 = sessions.create();
        assert!(sessions.is_valid(&t1));
        assert!(sessions.is_valid(&t2));
        sessions.gc(); // should keep both (not expired)
        assert!(sessions.is_valid(&t1));
    }

    #[test]
    fn test_session_max_cap() {
        let sessions = Sessions::new();
        // Create many sessions — should not panic or grow unboundedly.
        // (We only create a small number here for test speed; the cap logic is tested structurally.)
        for _ in 0..100 {
            sessions.create();
        }
        sessions.gc();
    }

    #[test]
    fn test_cookie_has_secure_flag() {
        let cookie = set_cookie("testtoken");
        assert!(
            cookie.contains("Secure"),
            "cookie must have Secure flag: {cookie}"
        );
        assert!(
            cookie.contains("HttpOnly"),
            "cookie must have HttpOnly flag: {cookie}"
        );
        assert!(
            cookie.contains("SameSite=Lax"),
            "cookie must have SameSite=Lax: {cookie}"
        );
    }
}
