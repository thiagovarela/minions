//! `minions-proxy` — HTTP reverse proxy for MINICLANKERS.COM.
//!
//! Runs on port 80 (or configurable). Cloudflare sits in front and handles
//! TLS termination (orange-cloud / proxy mode). Requests arrive here as plain
//! HTTP with `Host: <vmname>.miniclankers.com`.
//!
//! Routing:
//!   <vmname>.miniclankers.com  →  VM's internal IP:proxy_port
//!   miniclankers.com           →  apex landing page
//!   /__minions/login            →  login / logout (for private VMs)

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, routing::any};
use tracing::info;

pub mod auth;
pub mod db;
pub mod proxy;

pub use proxy::AppState;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProxyConfig {
    /// Path to the shared SQLite DB.
    pub db_path: String,
    /// Base domain, e.g. "miniclankers.com".
    pub domain: String,
    /// Optional API key — used as the proxy password for private VMs.
    pub api_key: Option<String>,
}

// ── Serve ─────────────────────────────────────────────────────────────────────

pub async fn serve(config: ProxyConfig, bind: &str) -> Result<()> {
    // Run the DB migration for proxy columns up-front.
    {
        let conn = db::open(&config.db_path).context("open db for proxy migration")?;
        db::migrate(&conn).context("proxy db migration")?;
    }

    let state = AppState {
        db_path: Arc::new(config.db_path),
        domain: Arc::new(config.domain.clone()),
        api_key: config.api_key.map(Arc::new),
        sessions: auth::Sessions::new(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build http client")?,
    };

    let app = Router::new()
        .fallback(any(proxy::handle))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind proxy to {bind}"))?;

    info!("HTTP proxy listening on http://{bind} (domain: {})", config.domain);
    axum::serve(listener, app).await.context("proxy serve")
}
