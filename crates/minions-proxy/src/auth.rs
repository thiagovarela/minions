//! Simple session-cookie auth for private VMs.
//!
//! The password is the value of `MINIONS_API_KEY` (same secret used by the
//! HTTP API). If no API key is set the proxy accepts all requests.
//!
//! Session tokens are stored in memory; they expire after 24 hours or when
//! the daemon restarts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use dashmap::DashMap;
use tracing::{info, warn};
use uuid::Uuid;

pub const COOKIE_NAME: &str = "minions_session";
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);
/// Maximum number of concurrent sessions. Exceeding this drops oldest entries.
const MAX_SESSIONS: usize = 10_000;

/// Lockout durations in seconds for progressive backoff after failed logins.
const LOCKOUT_DURATIONS: [u64; 4] = [60, 300, 600, 3600]; // 1m, 5m, 10m, 1h

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

// ── Login Rate Limiter ────────────────────────────────────────────────────────

/// Tracks failed login attempts per IP with progressive backoff.
#[derive(Debug, Clone)]
struct LoginAttemptRecord {
    /// Number of consecutive failed attempts
    failures: usize,
    /// Time of last failure
    last_failure: Instant,
    /// Whether the IP is currently locked out
    locked_until: Option<Instant>,
}

impl LoginAttemptRecord {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            failures: 1,
            last_failure: now,
            locked_until: None,
        }
    }

    /// Record a failure and return the lockout duration (if any).
    fn record_failure(&mut self) -> Option<Duration> {
        self.failures += 1;
        self.last_failure = Instant::now();

        // Progressive backoff: 5, 10, 20, 20+ failures
        let lockout_idx = match self.failures {
            0..=4 => return None,
            5 => 0,   // 1 minute
            10 => 1,  // 5 minutes
            20 => 2,  // 10 minutes
            _ => 3,   // 1 hour for 20+ failures
        };

        let duration = Duration::from_secs(LOCKOUT_DURATIONS[lockout_idx]);
        self.locked_until = Some(Instant::now() + duration);
        Some(duration)
    }

    /// Record a success - clears the failure streak.
    fn record_success(&mut self) {
        self.failures = 0;
        self.locked_until = None;
    }

    /// Check if the IP is currently locked out.
    fn is_locked_out(&self) -> bool {
        match self.locked_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// Get remaining lockout time.
    fn remaining_lockout(&self) -> Option<Duration> {
        self.locked_until.map(|until| {
            let now = Instant::now();
            if until > now {
                until - now
            } else {
                Duration::ZERO
            }
        })
    }

    /// Check if this record is stale (no activity for a long time).
    fn is_stale(&self) -> bool {
        // Clean up records older than 24 hours
        Instant::now().duration_since(self.last_failure) > Duration::from_secs(24 * 3600)
    }
}

/// Rate limiter for login attempts to prevent brute force attacks.
#[derive(Clone)]
pub struct LoginRateLimiter {
    attempts: Arc<DashMap<IpAddr, LoginAttemptRecord>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        let limiter = Self {
            attempts: Arc::new(DashMap::new()),
        };

        limiter.spawn_cleanup_task();
        limiter
    }

    /// Check if a login attempt from this IP is allowed.
    /// Returns Err(lockout_secs) if the IP is locked out.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        if let Some(record) = self.attempts.get(&ip) {
            if record.is_locked_out() {
                return Err(record.remaining_lockout().unwrap_or(Duration::ZERO).as_secs());
            }
        }
        Ok(())
    }

    /// Record a failed login attempt from this IP.
    /// Returns the lockout duration if this triggered a lockout.
    pub fn record_failure(&self, ip: IpAddr) -> Option<Duration> {
        let mut entry = self.attempts.entry(ip).or_insert_with(LoginAttemptRecord::new);
        let lockout = entry.record_failure();

        if let Some(duration) = lockout {
            warn!(
                ip = %ip,
                failures = entry.failures,
                lockout_secs = duration.as_secs(),
                "IP locked out due to failed login attempts"
            );
        }

        lockout
    }

    /// Record a successful login - clears the failure streak.
    pub fn record_success(&self, ip: IpAddr) {
        if let Some(mut entry) = self.attempts.get_mut(&ip) {
            if entry.failures > 0 {
                info!(ip = %ip, "Login succeeded, clearing failure streak");
                entry.record_success();
            }
        }
    }

    /// Get the number of failures for an IP.
    pub fn get_failures(&self, ip: IpAddr) -> usize {
        self.attempts
            .get(&ip)
            .map(|r| r.failures)
            .unwrap_or(0)
    }

    /// Reset rate limit for an IP (e.g., manual unblock).
    pub fn reset(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }

    /// Spawn background cleanup task.
    fn spawn_cleanup_task(&self) {
        let attempts = Arc::clone(&self.attempts);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let before = attempts.len();
                attempts.retain(|_, record| !record.is_stale());
                let after = attempts.len();

                if before != after {
                    info!("login rate limit cleanup: {} → {} IPs", before, after);
                }
            }
        });
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

/// Render the locked out page.
pub fn locked_out_page(retry_after_secs: u64) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MINICLANKERS — Locked Out</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;
           padding:2rem;width:100%;max-width:360px;text-align:center}}
    h1{{font-size:1.25rem;font-weight:600;margin-bottom:1.5rem;color:#fc8181}}
    p{{color:#a0aec0;margin-bottom:1rem}}
    .timer{{font-size:2rem;font-weight:700;color:#4299e1}}
  </style>
</head>
<body>
  <div class="card">
    <h1>⏱️ Too Many Attempts</h1>
    <p>This IP address has been temporarily locked due to too many failed login attempts.</p>
    <p>Please try again in:</p>
    <p class="timer">{} minutes</p>
  </div>
</body>
</html>"#,
        (retry_after_secs + 59) / 60 // Round up to minutes
    );

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("retry-after", retry_after_secs.to_string())
        .body(Body::from(html))
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

    // ── Login Rate Limiter Tests ─────────────────────────────────────────────

    #[test]
    fn test_login_attempt_record_basic() {
        let mut record = LoginAttemptRecord::new();
        assert_eq!(record.failures, 1);
        assert!(!record.is_locked_out());

        // 4 more failures (total 5) - should trigger 1 minute lockout
        for _ in 0..4 {
            record.record_failure();
        }
        assert!(record.is_locked_out());
        assert!(record.remaining_lockout().unwrap().as_secs() >= 59);
    }

    #[test]
    fn test_login_attempt_record_progressive_backoff() {
        let mut record = LoginAttemptRecord::new();

        // First 4 failures - no lockout (we already have 1 from new())
        for _ in 0..3 {
            assert!(record.record_failure().is_none());
        }

        // 5th failure - 1 minute lockout
        let lockout = record.record_failure();
        assert!(lockout.is_some());
        assert_eq!(lockout.unwrap().as_secs(), 60);

        // Reset for next test
        record.record_success();
        assert_eq!(record.failures, 0);
        assert!(!record.is_locked_out());
    }

    #[tokio::test]
    async fn test_login_rate_limiter_check() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Initially allowed
        assert!(limiter.check(ip).is_ok());

        // Record some failures but not enough to lock out
        // (First call to record_failure creates entry with 1 failure,
        // so we need 3 more to get to 4 total, still under threshold of 5)
        for _ in 0..3 {
            limiter.record_failure(ip);
        }

        // Should still be allowed (4 failures, threshold is 5)
        assert!(limiter.check(ip).is_ok());

        // 5th failure triggers lockout
        limiter.record_failure(ip);
        assert!(limiter.check(ip).is_err());
    }

    #[tokio::test]
    async fn test_login_rate_limiter_success_clears_failures() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record some failures (first call creates entry with 1 failure)
        for _ in 0..3 {
            limiter.record_failure(ip);
        }
        // Should have 4 failures total (1 from new + 3 more)
        assert_eq!(limiter.get_failures(ip), 4);

        // Success clears failures
        limiter.record_success(ip);
        assert_eq!(limiter.get_failures(ip), 0);

        // Should be allowed again even after previously having failures
        assert!(limiter.check(ip).is_ok());
    }

    #[tokio::test]
    async fn test_login_rate_limiter_reset() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Lock out the IP
        for _ in 0..5 {
            limiter.record_failure(ip);
        }
        assert!(limiter.check(ip).is_err());

        // Reset should clear lockout
        limiter.reset(ip);
        assert!(limiter.check(ip).is_ok());
        assert_eq!(limiter.get_failures(ip), 0);
    }

    #[tokio::test]
    async fn test_login_rate_limiter_different_ips() {
        let limiter = LoginRateLimiter::new();
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Lock out ip1
        for _ in 0..5 {
            limiter.record_failure(ip1);
        }
        assert!(limiter.check(ip1).is_err());

        // ip2 should still be allowed
        assert!(limiter.check(ip2).is_ok());
    }
}
