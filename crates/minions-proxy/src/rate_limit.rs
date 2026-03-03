//! Request rate limiting for the HTTPS proxy.
//!
//! Provides sliding window rate limiting per IP address with automatic
//! cleanup of stale entries. Used to prevent DoS attacks and brute force
//! attempts.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use dashmap::DashMap;
use tracing::{debug, warn};

/// Configuration for rate limiting.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum requests per window per IP (default: 100)
    pub max_requests: usize,
    /// Window duration in seconds (default: 60)
    pub window_secs: u64,
    /// Enable rate limiting (default: true)
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 1000,
            window_secs: 60,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let max_requests = std::env::var("MINIONS_RATE_LIMIT_RPM")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let window_secs = std::env::var("MINIONS_RATE_LIMIT_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);

        let enabled = std::env::var("MINIONS_RATE_LIMIT_ENABLED")
            .ok()
            .map(|s| s != "false" && s != "0")
            .unwrap_or(true);

        Self {
            max_requests,
            window_secs,
            enabled,
        }
    }
}

/// A single request window for an IP address.
#[derive(Debug)]
struct RequestWindow {
    /// Timestamps of requests in the current window
    requests: Vec<Instant>,
    /// Last time this window was accessed (for cleanup)
    last_accessed: Instant,
}

impl RequestWindow {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            requests: Vec::with_capacity(16),
            last_accessed: now,
        }
    }

    /// Add a request and return whether it's allowed.
    fn add_request(&mut self, max_requests: usize, window: Duration) -> bool {
        let now = Instant::now();
        self.last_accessed = now;

        // Remove requests outside the window
        self.requests.retain(|&t| now.duration_since(t) < window);

        // Check if we're under the limit
        if self.requests.len() >= max_requests {
            return false;
        }

        self.requests.push(now);
        true
    }

    /// Check if this window is stale (no activity for a long time).
    fn is_stale(&self, stale_duration: Duration) -> bool {
        Instant::now().duration_since(self.last_accessed) > stale_duration
    }
}

/// Per-IP rate limiter with sliding window.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of IP addresses to their request windows
    windows: Arc<DashMap<IpAddr, RequestWindow>>,
    /// Configuration
    pub config: RateLimitConfig,
    /// Duration after which an inactive window is removed
    stale_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            windows: Arc::new(DashMap::new()),
            config,
            stale_duration: Duration::from_secs(300), // 5 minutes
        };

        // Spawn cleanup task if enabled
        if limiter.config.enabled {
            limiter.spawn_cleanup_task();
        }

        limiter
    }

    /// Check if a request from the given IP should be allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        if !self.config.enabled {
            return true;
        }

        let window = Duration::from_secs(self.config.window_secs);
        let max = self.config.max_requests;

        match self.windows.entry(ip) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                e.get_mut().add_request(max, window)
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                let mut rw = RequestWindow::new();
                let allowed = rw.add_request(max, window);
                e.insert(rw);
                allowed
            }
        }
    }

    /// Get the number of remaining requests for an IP.
    pub fn remaining(&self, ip: IpAddr) -> usize {
        if !self.config.enabled {
            return self.config.max_requests;
        }

        let window = Duration::from_secs(self.config.window_secs);

        if let Some(mut e) = self.windows.get_mut(&ip) {
            let now = Instant::now();
            e.requests.retain(|&t| now.duration_since(t) < window);
            self.config.max_requests.saturating_sub(e.requests.len())
        } else {
            self.config.max_requests
        }
    }

    /// Reset rate limit for a specific IP (e.g., after manual unblock).
    pub fn reset(&self, ip: IpAddr) {
        self.windows.remove(&ip);
    }

    /// Get current stats for monitoring.
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            tracked_ips: self.windows.len(),
            max_requests: self.config.max_requests,
            window_secs: self.config.window_secs,
        }
    }

    /// Spawn a background task to clean up stale windows.
    fn spawn_cleanup_task(&self) {
        let windows = Arc::clone(&self.windows);
        let stale = self.stale_duration;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let before = windows.len();
                windows.retain(|_, window| !window.is_stale(stale));
                let after = windows.len();

                if before != after {
                    debug!("rate limit cleanup: {} → {} IPs", before, after);
                }
            }
        });
    }
}

/// Rate limiter statistics for monitoring.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitStats {
    pub tracked_ips: usize,
    pub max_requests: usize,
    pub window_secs: u64,
}

/// Extract client IP from request headers or connection info.
///
/// Checks X-Forwarded-For, X-Real-IP headers (in order), falling back
/// to the socket address if no headers are present.
pub fn extract_client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    // Check X-Forwarded-For header (common for reverse proxies)
    if let Some(value) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = value.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // We want the first (client) IP
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Check X-Real-IP header (nginx, etc.)
    if let Some(value) = req.headers().get("x-real-ip") {
        if let Ok(s) = value.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Note: The actual socket address requires connection info from axum
    // This is handled by the caller who has access to ConnectInfo
    None
}

/// Build a rate limit exceeded response.
pub fn rate_limit_response(retry_after_secs: u64) -> Response {
    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>429 Too Many Requests</title>
  <style>
    body{{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
    .box{{text-align:center}}
    h1{{font-size:4rem;font-weight:700;color:#fc8181;margin:0}}
    p{{color:#a0aec0;margin-top:.5rem}}
  </style>
</head>
<body>
  <div class="box">
    <h1>429</h1>
    <p>Too many requests. Please slow down.</p>
    <p>Retry after: {} seconds</p>
  </div>
</body>
</html>"#,
        retry_after_secs
    );

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "text/html; charset=utf-8")
        .header("retry-after", retry_after_secs.to_string())
        .body(Body::from(body))
        .unwrap()
}

/// Middleware to check rate limits for incoming requests.
pub async fn rate_limit_middleware<B>(
    rate_limiter: &RateLimiter,
    ip: IpAddr,
    req: Request<B>,
    next: impl FnOnce(Request<B>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>,
) -> Response {
    if rate_limiter.check(ip) {
        next(req).await
    } else {
        warn!(ip = %ip, "rate limit exceeded");
        rate_limit_response(rate_limiter.config.window_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_request_window_basic() {
        let mut window = RequestWindow::new();
        let dur = Duration::from_secs(60);

        // Should allow up to max_requests
        for i in 0..100 {
            assert!(window.add_request(100, dur), "request {} should be allowed", i);
        }

        // 101st request should be denied
        assert!(!window.add_request(100, dur), "request 101 should be denied");
    }

    #[test]
    fn test_request_window_sliding() {
        let mut window = RequestWindow::new();
        let dur = Duration::from_millis(100);

        // Add 5 requests
        for _ in 0..5 {
            assert!(window.add_request(5, dur));
        }

        // 6th should be denied
        assert!(!window.add_request(5, dur));

        // Wait for window to slide
        thread::sleep(dur + Duration::from_millis(10));

        // Should be allowed again
        assert!(window.add_request(5, dur));
    }

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let config = RateLimitConfig {
            max_requests: 5,
            window_secs: 60,
            enabled: true,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 5 should pass
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }

        // 6th should fail
        assert!(!limiter.check(ip));
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            max_requests: 2,
            window_secs: 60,
            enabled: true,
        };

        let limiter = RateLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Use up ip1's quota
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1));

        // ip2 should still have quota
        assert!(limiter.check(ip2));
        assert!(limiter.check(ip2));
        assert!(!limiter.check(ip2));
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            max_requests: 1,
            window_secs: 60,
            enabled: false,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should always allow when disabled
        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let config = RateLimitConfig {
            max_requests: 2,
            window_secs: 60,
            enabled: true,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Use up quota
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));

        // Reset and try again
        limiter.reset(ip);
        assert!(limiter.check(ip));
    }

    #[tokio::test]
    async fn test_remaining() {
        let config = RateLimitConfig {
            max_requests: 5,
            window_secs: 60,
            enabled: true,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert_eq!(limiter.remaining(ip), 5);
        limiter.check(ip);
        assert_eq!(limiter.remaining(ip), 4);
        limiter.check(ip);
        assert_eq!(limiter.remaining(ip), 3);
    }

    #[test]
    fn test_extract_client_ip_forwarded() {
        use axum::http::Request;

        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.195, 70.41.3.18, 150.172.238.178")
            .body(())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("203.0.113.195".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_real_ip() {
        use axum::http::Request;

        let req = Request::builder()
            .header("x-real-ip", "192.168.1.100")
            .body(())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_priority() {
        use axum::http::Request;

        // X-Forwarded-For should take priority over X-Real-IP
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.1")
            .header("x-real-ip", "192.168.1.100")
            .body(())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
    }
}
