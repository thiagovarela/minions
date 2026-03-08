//! Lightweight Prometheus-style metrics for `minions-proxy`.
//!
//! We keep counters/histograms in memory and expose them through a `/metrics`
//! endpoint without pulling in an external Prometheus crate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::http::StatusCode;

use crate::connection_limit::ConnectionLimiter;
use crate::rate_limit::RateLimiter;

#[derive(Debug, Clone, Default)]
pub struct ProxyMetrics {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    inflight_requests: AtomicI64,
    requests_total: RwLock<HashMap<RequestLabels, u64>>,
    request_duration: RwLock<HashMap<DurationLabels, Histogram>>,
    upstream_errors_total: RwLock<HashMap<ErrorLabels, u64>>,
    websocket_upgrades_total: AtomicU64,
    websocket_upgrade_failures_total: AtomicU64,
    rate_limit_denied_total: AtomicU64,
    connection_limit_denied_total: AtomicU64,
    auth_redirects_total: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestLabels {
    method: String,
    route_kind: String,
    status: u16,
    status_class: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DurationLabels {
    method: String,
    route_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ErrorLabels {
    route_kind: String,
    kind: String,
}

#[derive(Debug, Clone)]
pub struct RequestTracker {
    metrics: ProxyMetrics,
    method: String,
    route_kind: String,
    started_at: Instant,
    finished: bool,
}

#[derive(Debug, Clone, Copy)]
struct Histogram {
    buckets: [u64; HISTOGRAM_BOUNDS.len()],
    count: u64,
    sum_secs: f64,
}

const HISTOGRAM_BOUNDS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: [0; HISTOGRAM_BOUNDS.len()],
            count: 0,
            sum_secs: 0.0,
        }
    }
}

impl Histogram {
    fn observe(&mut self, secs: f64) {
        for (idx, bound) in HISTOGRAM_BOUNDS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[idx] += 1;
            }
        }
        self.count += 1;
        self.sum_secs += secs;
    }
}

impl ProxyMetrics {
    pub fn start_request(&self, method: &str, route_kind: &str) -> RequestTracker {
        self.inner.inflight_requests.fetch_add(1, Ordering::Relaxed);
        RequestTracker {
            metrics: self.clone(),
            method: method.to_string(),
            route_kind: route_kind.to_string(),
            started_at: Instant::now(),
            finished: false,
        }
    }

    fn finish_request(&self, method: &str, route_kind: &str, status: StatusCode, started_at: Instant) {
        self.inner.inflight_requests.fetch_sub(1, Ordering::Relaxed);

        let labels = RequestLabels {
            method: method.to_string(),
            route_kind: route_kind.to_string(),
            status: status.as_u16(),
            status_class: status_class(status),
        };
        if let Ok(mut requests) = self.inner.requests_total.write() {
            *requests.entry(labels).or_insert(0) += 1;
        }

        let duration_labels = DurationLabels {
            method: method.to_string(),
            route_kind: route_kind.to_string(),
        };
        if let Ok(mut durations) = self.inner.request_duration.write() {
            durations
                .entry(duration_labels)
                .or_default()
                .observe(started_at.elapsed().as_secs_f64());
        }
    }

    pub fn record_upstream_error(&self, route_kind: &str, kind: &str) {
        if let Ok(mut errors) = self.inner.upstream_errors_total.write() {
            *errors
                .entry(ErrorLabels {
                    route_kind: route_kind.to_string(),
                    kind: kind.to_string(),
                })
                .or_insert(0) += 1;
        }
    }

    pub fn inc_websocket_upgrade(&self) {
        self.inner
            .websocket_upgrades_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_websocket_upgrade_failure(&self) {
        self.inner
            .websocket_upgrade_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limit_denied(&self) {
        self.inner
            .rate_limit_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connection_limit_denied(&self) {
        self.inner
            .connection_limit_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_redirect(&self) {
        self.inner.auth_redirects_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn prometheus_text(
        &self,
        host: &str,
        rate_limiter: &RateLimiter,
        connection_limiter: &ConnectionLimiter,
    ) -> String {
        let mut out = String::with_capacity(8192);

        gauge(
            &mut out,
            "minions_proxy_http_inflight_requests",
            "Current number of in-flight proxy requests",
            &[(vec![("host", host)], self.inner.inflight_requests.load(Ordering::Relaxed) as f64)],
        );

        counter(
            &mut out,
            "minions_proxy_websocket_upgrades_total",
            "Successful websocket upgrade attempts proxied to upstreams",
            &[(vec![("host", host)], self.inner.websocket_upgrades_total.load(Ordering::Relaxed) as f64)],
        );
        counter(
            &mut out,
            "minions_proxy_websocket_upgrade_failures_total",
            "Failed websocket upgrade attempts",
            &[(vec![("host", host)], self.inner.websocket_upgrade_failures_total.load(Ordering::Relaxed) as f64)],
        );
        counter(
            &mut out,
            "minions_proxy_rate_limit_denied_total",
            "Requests denied by the IP rate limiter",
            &[(vec![("host", host)], self.inner.rate_limit_denied_total.load(Ordering::Relaxed) as f64)],
        );
        counter(
            &mut out,
            "minions_proxy_connection_limit_denied_total",
            "Requests denied by the connection limiter",
            &[(vec![("host", host)], self.inner.connection_limit_denied_total.load(Ordering::Relaxed) as f64)],
        );
        counter(
            &mut out,
            "minions_proxy_auth_redirects_total",
            "Requests redirected to login for private VMs",
            &[(vec![("host", host)], self.inner.auth_redirects_total.load(Ordering::Relaxed) as f64)],
        );

        let rl = rate_limiter.stats();
        gauge(
            &mut out,
            "minions_proxy_rate_limit_tracked_ips",
            "Number of IPs currently tracked by the rate limiter",
            &[(vec![("host", host)], rl.tracked_ips as f64)],
        );
        gauge(
            &mut out,
            "minions_proxy_rate_limit_max_requests",
            "Configured max requests per rate-limit window",
            &[(vec![("host", host)], rl.max_requests as f64)],
        );
        gauge(
            &mut out,
            "minions_proxy_rate_limit_window_seconds",
            "Configured rate-limit window in seconds",
            &[(vec![("host", host)], rl.window_secs as f64)],
        );

        let cl = connection_limiter.stats();
        gauge(
            &mut out,
            "minions_proxy_connections_active",
            "Current number of active proxy connections",
            &[(vec![("host", host)], cl.total as f64)],
        );
        gauge(
            &mut out,
            "minions_proxy_connections_unique_ips",
            "Number of IPs with active proxy connections",
            &[(vec![("host", host)], cl.unique_ips as f64)],
        );
        gauge(
            &mut out,
            "minions_proxy_connections_limit_total",
            "Configured max total concurrent proxy connections",
            &[(vec![("host", host)], cl.max_total as f64)],
        );
        gauge(
            &mut out,
            "minions_proxy_connections_limit_per_ip",
            "Configured max concurrent proxy connections per IP",
            &[(vec![("host", host)], cl.max_per_ip as f64)],
        );

        let request_samples = self
            .inner
            .requests_total
            .read()
            .ok()
            .map(|map| {
                map.iter()
                    .map(|(labels, count)| {
                        (
                            vec![
                                ("host", host.to_string()),
                                ("method", labels.method.clone()),
                                ("route_kind", labels.route_kind.clone()),
                                ("status", labels.status.to_string()),
                                ("status_class", labels.status_class.to_string()),
                            ],
                            *count as f64,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        counter_owned(
            &mut out,
            "minions_proxy_http_requests_total",
            "HTTP requests handled by the proxy",
            &request_samples,
        );

        let error_samples = self
            .inner
            .upstream_errors_total
            .read()
            .ok()
            .map(|map| {
                map.iter()
                    .map(|(labels, count)| {
                        (
                            vec![
                                ("host", host.to_string()),
                                ("route_kind", labels.route_kind.clone()),
                                ("kind", labels.kind.clone()),
                            ],
                            *count as f64,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        counter_owned(
            &mut out,
            "minions_proxy_upstream_errors_total",
            "Upstream errors seen while proxying requests",
            &error_samples,
        );

        let durations = self
            .inner
            .request_duration
            .read()
            .ok()
            .map(|map| map.clone())
            .unwrap_or_default();
        histogram_owned(
            &mut out,
            "minions_proxy_http_request_duration_seconds",
            "End-to-end proxy request duration in seconds",
            &durations,
            host,
        );

        out
    }
}

impl RequestTracker {
    pub fn finish(mut self, status: StatusCode) -> StatusCode {
        self.metrics
            .finish_request(&self.method, &self.route_kind, status, self.started_at);
        self.finished = true;
        status
    }
}

impl Drop for RequestTracker {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.finish_request(
                &self.method,
                &self.route_kind,
                StatusCode::INTERNAL_SERVER_ERROR,
                self.started_at,
            );
            self.finished = true;
        }
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "unknown",
    }
}

fn gauge(out: &mut String, name: &str, help: &str, samples: &[(Vec<(&str, &str)>, f64)]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} gauge\n"));
    for (labels, value) in samples {
        write_sample(out, name, labels, *value);
    }
}

fn counter(out: &mut String, name: &str, help: &str, samples: &[(Vec<(&str, &str)>, f64)]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (labels, value) in samples {
        write_sample(out, name, labels, *value);
    }
}

fn counter_owned(out: &mut String, name: &str, help: &str, samples: &[(Vec<(impl AsRef<str>, impl AsRef<str>)>, f64)]) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} counter\n"));
    for (labels, value) in samples {
        let owned = labels
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
            .collect::<Vec<_>>();
        write_sample(out, name, &owned, *value);
    }
}

fn histogram_owned(
    out: &mut String,
    name: &str,
    help: &str,
    samples: &HashMap<DurationLabels, Histogram>,
    host: &str,
) {
    out.push_str(&format!("# HELP {name} {help}\n"));
    out.push_str(&format!("# TYPE {name} histogram\n"));
    for (labels, hist) in samples {
        for (idx, bound) in HISTOGRAM_BOUNDS.iter().enumerate() {
            let mut sample_labels = vec![
                ("host", host),
                ("method", labels.method.as_str()),
                ("route_kind", labels.route_kind.as_str()),
            ];
            let bound_str = bound.to_string();
            sample_labels.push(("le", bound_str.as_str()));
            write_sample(out, &format!("{name}_bucket"), &sample_labels, hist.buckets[idx] as f64);
        }
        let inf_labels = vec![
            ("host", host),
            ("method", labels.method.as_str()),
            ("route_kind", labels.route_kind.as_str()),
            ("le", "+Inf"),
        ];
        write_sample(out, &format!("{name}_bucket"), &inf_labels, hist.count as f64);
        let base_labels = vec![
            ("host", host),
            ("method", labels.method.as_str()),
            ("route_kind", labels.route_kind.as_str()),
        ];
        write_sample(out, &format!("{name}_sum"), &base_labels, hist.sum_secs);
        write_sample(out, &format!("{name}_count"), &base_labels, hist.count as f64);
    }
}

fn write_sample(out: &mut String, name: &str, labels: &[(impl AsRef<str>, impl AsRef<str>)], value: f64) {
    if labels.is_empty() {
        out.push_str(&format!("{name} {value}\n"));
        return;
    }

    let label_str = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k.as_ref(), escape_label_value(v.as_ref())))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!("{name}{{{label_str}}} {value}\n"));
}

fn escape_label_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"")
}
