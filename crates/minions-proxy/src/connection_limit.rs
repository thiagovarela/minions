//! Connection limiter for the HTTPS proxy.
//!
//! Tracks active connections globally and per-IP to prevent resource exhaustion.
//! When limits are exceeded, new connections are rejected.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use dashmap::DashMap;
use tracing::{info, warn};

/// Configuration for connection limiting.
#[derive(Clone, Debug)]
pub struct ConnectionLimitConfig {
    /// Maximum total concurrent connections (default: 10,000)
    pub max_total: usize,
    /// Maximum concurrent connections per IP (default: 50)
    pub max_per_ip: usize,
    /// Enable connection limiting (default: true)
    pub enabled: bool,
}

impl Default for ConnectionLimitConfig {
    fn default() -> Self {
        Self {
            max_total: 10_000,
            max_per_ip: 50,
            enabled: true,
        }
    }
}

impl ConnectionLimitConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let max_total = std::env::var("MINIONS_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);

        let max_per_ip = std::env::var("MINIONS_MAX_CONNECTIONS_PER_IP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50);

        let enabled = std::env::var("MINIONS_CONNECTION_LIMIT_ENABLED")
            .ok()
            .map(|s| s != "false" && s != "0")
            .unwrap_or(true);

        Self {
            max_total,
            max_per_ip,
            enabled,
        }
    }
}

/// Connection limiter that tracks active connections globally and per-IP.
#[derive(Clone)]
pub struct ConnectionLimiter {
    /// Total active connections
    total: Arc<AtomicUsize>,
    /// Per-IP active connection counts
    per_ip: Arc<DashMap<IpAddr, AtomicUsize>>,
    /// Configuration
    config: ConnectionLimitConfig,
}

impl ConnectionLimiter {
    /// Create a new connection limiter.
    pub fn new(config: ConnectionLimitConfig) -> Self {
        let limiter = Self {
            total: Arc::new(AtomicUsize::new(0)),
            per_ip: Arc::new(DashMap::new()),
            config,
        };

        if limiter.config.enabled {
            limiter.spawn_cleanup_task();
        }

        limiter
    }

    /// Try to acquire a connection slot for the given IP.
    /// Returns `Some(ConnectionGuard)` if successful, `None` if limits exceeded.
    pub fn acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        if !self.config.enabled {
            return Some(ConnectionGuard::new_disabled());
        }

        // Check global limit first
        let current_total = self.total.load(Ordering::Relaxed);
        if current_total >= self.config.max_total {
            warn!(
                "Global connection limit exceeded: {}/{}",
                current_total, self.config.max_total
            );
            return None;
        }

        // Check per-IP limit
        let ip_count = self
            .per_ip
            .entry(ip)
            .or_insert_with(|| AtomicUsize::new(0));
        let current_ip = ip_count.load(Ordering::Relaxed);

        if current_ip >= self.config.max_per_ip {
            warn!(
                "Per-IP connection limit exceeded for {}: {}/{}",
                ip, current_ip, self.config.max_per_ip
            );
            return None;
        }

        // Increment counters
        self.total.fetch_add(1, Ordering::Relaxed);
        ip_count.fetch_add(1, Ordering::Relaxed);

        Some(ConnectionGuard::new(
            Arc::clone(&self.total),
            Arc::clone(&self.per_ip),
            ip,
        ))
    }

    /// Get current connection statistics.
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            total: self.total.load(Ordering::Relaxed),
            unique_ips: self.per_ip.len(),
            max_total: self.config.max_total,
            max_per_ip: self.config.max_per_ip,
        }
    }

    /// Spawn a background task to clean up stale IP entries.
    fn spawn_cleanup_task(&self) {
        let per_ip = Arc::clone(&self.per_ip);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                // Remove IP entries with 0 connections
                let before = per_ip.len();
                per_ip.retain(|_, count| count.load(Ordering::Relaxed) > 0);
                let after = per_ip.len();

                if before != after {
                    info!("connection limiter cleanup: {} → {} IPs", before, after);
                }
            }
        });
    }
}

/// Statistics about current connections.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionStats {
    pub total: usize,
    pub unique_ips: usize,
    pub max_total: usize,
    pub max_per_ip: usize,
}

/// Guard that decrements connection counters when dropped.
pub struct ConnectionGuard {
    total: Option<Arc<AtomicUsize>>,
    per_ip: Option<Arc<DashMap<IpAddr, AtomicUsize>>>,
    ip: Option<IpAddr>,
}

impl ConnectionGuard {
    /// Create a new guard for an enabled limiter.
    fn new(
        total: Arc<AtomicUsize>,
        per_ip: Arc<DashMap<IpAddr, AtomicUsize>>,
        ip: IpAddr,
    ) -> Self {
        Self {
            total: Some(total),
            per_ip: Some(per_ip),
            ip: Some(ip),
        }
    }

    /// Create a disabled guard (no-op on drop).
    fn new_disabled() -> Self {
        Self {
            total: None,
            per_ip: None,
            ip: None,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(ref total) = self.total {
            total.fetch_sub(1, Ordering::Relaxed);
        }

        if let (Some(per_ip), Some(ip)) = (&self.per_ip, self.ip) {
            if let Some(count) = per_ip.get(&ip) {
                count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Build a connection limit exceeded response.
pub fn connection_limit_response() -> Response {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>503 Service Unavailable</title>
  <style>
    body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;
          display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .box{text-align:center}
    h1{font-size:4rem;font-weight:700;color:#fc8181;margin:0}
    p{color:#a0aec0;margin-top:.5rem}
  </style>
</head>
<body>
  <div class="box">
    <h1>503</h1>
    <p>Server is at capacity. Please try again later.</p>
  </div>
</body>
</html>"#;

    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "text/html; charset=utf-8")
        .header("retry-after", "30")
        .body(Body::from(html))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_limiter_basic() {
        let config = ConnectionLimitConfig {
            max_total: 5,
            max_per_ip: 2,
            enabled: true,
        };

        let limiter = ConnectionLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Acquire up to per-IP limit
        let guard1 = limiter.acquire(ip);
        assert!(guard1.is_some());

        let guard2 = limiter.acquire(ip);
        assert!(guard2.is_some());

        // Third should fail (per-IP limit = 2)
        let guard3 = limiter.acquire(ip);
        assert!(guard3.is_none());

        // Different IP should still work (total = 2/5)
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let guard4 = limiter.acquire(ip2);
        assert!(guard4.is_some());
    }

    #[tokio::test]
    async fn test_connection_limiter_global() {
        let config = ConnectionLimitConfig {
            max_total: 2,
            max_per_ip: 10,
            enabled: true,
        };

        let limiter = ConnectionLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        // Acquire 2 connections from different IPs
        let _guard1 = limiter.acquire(ip1);
        let _guard2 = limiter.acquire(ip2);

        // Third should fail (global limit = 2)
        let guard3 = limiter.acquire(ip3);
        assert!(guard3.is_none());
    }

    #[tokio::test]
    async fn test_connection_guard_drop() {
        let config = ConnectionLimitConfig {
            max_total: 5,
            max_per_ip: 5,
            enabled: true,
        };

        let limiter = ConnectionLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Acquire and release
        {
            let _guard = limiter.acquire(ip);
            assert_eq!(limiter.stats().total, 1);
        }

        // After drop, should be able to acquire again
        assert_eq!(limiter.stats().total, 0);
        let guard = limiter.acquire(ip);
        assert!(guard.is_some());
    }

    #[test]
    fn test_connection_limiter_disabled() {
        let config = ConnectionLimitConfig {
            max_total: 1,
            max_per_ip: 1,
            enabled: false,
        };

        let limiter = ConnectionLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should be able to acquire many when disabled
        for _ in 0..100 {
            let guard = limiter.acquire(ip);
            assert!(guard.is_some());
        }
    }

    #[tokio::test]
    async fn test_connection_stats() {
        let config = ConnectionLimitConfig {
            max_total: 100,
            max_per_ip: 10,
            enabled: true,
        };

        let limiter = ConnectionLimiter::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        let _guard1 = limiter.acquire(ip1);
        let _guard2 = limiter.acquire(ip1);
        let _guard3 = limiter.acquire(ip2);

        let stats = limiter.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.unique_ips, 2);
        assert_eq!(stats.max_total, 100);
        assert_eq!(stats.max_per_ip, 10);
    }
}
