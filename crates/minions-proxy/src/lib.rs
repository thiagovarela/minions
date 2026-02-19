//! `minions-proxy` — HTTPS reverse proxy with auto-TLS via Let's Encrypt.
//!
//! Listens on two ports:
//! - **Port 443** (HTTPS, TLS via rustls) — main proxy traffic
//! - **Port 80** (HTTP) — ACME HTTP-01 challenges + redirect to HTTPS
//!
//! Routing:
//!   <vmname>.miniclankers.com  →  VM's internal IP:proxy_port
//!   custom.example.com         →  VM's internal IP:proxy_port (custom domain)
//!   /__minions/login            →  login / logout (for private VMs)
//!
//! Certificate management:
//! - Wildcard `*.miniclankers.com` via DNS-01 (Cloudflare DNS API)
//! - Custom domains via HTTP-01 (automatic, no DNS access needed)
//! - Auto-renewal every 12 hours (renew 30 days before expiry)

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, routing::any, routing::get};
use tracing::{info, warn};

pub mod auth;
pub mod db;
pub mod proxy;
pub mod tls;
// Simplified TLS with manual cert provisioning (deprecated, kept for reference)
#[allow(dead_code)]
pub mod tls_simple;

pub use proxy::AppState;

/// ACME HTTP-01 challenge response map (token → key authorization).
pub type ChallengeMap = std::sync::Arc<dashmap::DashMap<String, String>>;

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ProxyConfig {
    /// Path to the shared SQLite DB.
    pub db_path: String,
    /// Base domain, e.g. "miniclankers.com".
    pub domain: String,
    /// Optional API key — used as the proxy password for private VMs.
    pub api_key: Option<String>,
    /// Certificate storage directory (default: /var/lib/minions/certs).
    pub certs_dir: String,
    /// Cloudflare DNS API token for DNS-01 wildcard challenges.
    pub cf_dns_token: Option<String>,
    /// Let's Encrypt account email.
    pub acme_email: String,
    /// Use Let's Encrypt staging environment (for testing).
    pub acme_staging: bool,
    /// Host public IP (for custom domain DNS verification).
    pub public_ip: Option<String>,
}

// ── Serve ─────────────────────────────────────────────────────────────────────

pub async fn serve(config: ProxyConfig, https_bind: &str, http_bind: &str) -> Result<()> {
    // Install a rustls crypto provider before any TLS operations.
    // Both aws-lc-rs and ring end up in the dependency graph (via reqwest + russh),
    // so rustls can't auto-select — we must call install_default() explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Run DB migration.
    {
        let conn = db::open(&config.db_path).context("open db for proxy migration")?;
        db::migrate(&conn).context("proxy db migration")?;
    }

    // Shared challenge response map for HTTP-01 ACME challenges.
    let challenges: ChallengeMap = Arc::new(dashmap::DashMap::new());

    // Initialize ACME client and provision wildcard cert if needed.
    let acme = Arc::new(
        tls::AcmeClient::new(
            &config.certs_dir,
            &config.acme_email,
            config.acme_staging,
            config.cf_dns_token.clone(),
            challenges.clone(),
        )
        .await
        .context("initialize ACME client")?,
    );

    // Provision wildcard cert for *.miniclankers.com if missing or expired.
    let wildcard = format!("*.{}", config.domain);
    if tls::CertStore::new(&config.certs_dir).needs_renewal(&wildcard) {
        info!(domain = %wildcard, "provisioning wildcard certificate");
        acme.provision_dns01_wildcard(&config.domain)
            .await
            .context("provision wildcard certificate")?;
    } else {
        info!(domain = %wildcard, "wildcard certificate already provisioned");
    }

    // Build SNI resolver.
    let sni_resolver = Arc::new(tls::SniResolver::new(
        config.domain.clone(),
        &config.certs_dir,
    ));

    // Preload wildcard cert into SNI cache.
    sni_resolver
        .load_and_cache(&wildcard)
        .context("load wildcard certificate")?;

    // Spawn background renewal task.
    tls::spawn_renewal_task(
        acme.clone(),
        sni_resolver.clone(),
        config.domain.clone(),
        config.db_path.clone(),
    );

    // Build TLS config with SNI resolver.
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver.clone());

    // Build shared app state.
    let state = AppState {
        db_path: Arc::new(config.db_path.clone()),
        domain: Arc::new(config.domain.clone()),
        api_key: config.api_key.map(Arc::new),
        public_ip: config.public_ip.map(Arc::new),
        sessions: auth::Sessions::new(),
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build http client")?,
        acme_challenges: challenges.clone(),
        acme_client: acme.clone(),
        sni_resolver: sni_resolver.clone(),
    };

    // HTTPS app (port 443) — main proxy.
    let https_app = Router::new()
        .fallback(any(proxy::handle))
        .with_state(state.clone());

    // HTTP app (port 80) — ACME challenges + redirect to HTTPS.
    let http_app = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(proxy::acme_challenge),
        )
        .fallback(any(proxy::http_redirect))
        .with_state(state);

    // Spawn HTTPS listener (port 443).
    let https_bind_clone = https_bind.to_string();
    let https_task = tokio::spawn(async move {
        info!("HTTPS proxy listening on https://{}", https_bind_clone);
        axum_server::bind_rustls(
            https_bind_clone.parse().expect("parse https bind addr"),
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_config)),
        )
        .serve(https_app.into_make_service())
        .await
        .expect("HTTPS server error");
    });

    // Spawn HTTP listener (port 80).
    let http_bind_clone = http_bind.to_string();
    let http_task = tokio::spawn(async move {
        info!(
            "HTTP listener on http://{} (ACME + redirect)",
            http_bind_clone
        );
        let listener = tokio::net::TcpListener::bind(&http_bind_clone)
            .await
            .expect("bind HTTP listener");
        axum::serve(listener, http_app)
            .await
            .expect("HTTP server error");
    });

    // Wait for both tasks (one will run forever unless error).
    tokio::select! {
        res = https_task => {
            if let Err(e) = res {
                warn!("HTTPS task error: {:#}", e);
            }
        }
        res = http_task => {
            if let Err(e) = res {
                warn!("HTTP task error: {:#}", e);
            }
        }
    }

    Ok(())
}
