//! Simplified TLS certificate management (stub for initial implementation).
//!
//! This is a minimal version to get the dual-port TLS infrastructure working.
//! Full ACME automation with instant-acme will be implemented in a follow-up.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

// ── Certificate Storage ───────────────────────────────────────────────────────

#[derive(Debug)]
pub struct CertStore {
    certs_dir: PathBuf,
}

impl CertStore {
    pub fn new(certs_dir: impl AsRef<Path>) -> Self {
        Self {
            certs_dir: certs_dir.as_ref().to_path_buf(),
        }
    }

    fn domain_dir(&self, domain: &str) -> PathBuf {
        self.certs_dir.join(domain)
    }

    /// Load certificate chain + private key from disk.
    pub fn load_cert(&self, domain: &str) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
        let dir = self.domain_dir(domain);
        let fullchain_path = dir.join("fullchain.pem");
        let privkey_path = dir.join("privkey.pem");

        if !fullchain_path.exists() || !privkey_path.exists() {
            return Ok(None);
        }

        let fullchain_pem = std::fs::read(&fullchain_path)
            .with_context(|| format!("read {}", fullchain_path.display()))?;
        let privkey_pem = std::fs::read(&privkey_path)
            .with_context(|| format!("read {}", privkey_path.display()))?;

        let certs = rustls_pemfile::certs(&mut &fullchain_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .context("parse certificate chain")?;

        let key = rustls_pemfile::private_key(&mut &privkey_pem[..])?
            .context("no private key found in privkey.pem")?;

        Ok(Some((certs, key)))
    }

    /// Check if a certificate needs renewal (stub - always returns false).
    pub fn needs_renewal(&self, _domain: &str) -> bool {
        // TODO: Parse cert expiry date
        false
    }
}

// ── Stub ACME Client ──────────────────────────────────────────────────────────

/// Placeholder for full ACME implementation.
/// For now, expects certificates to be manually provisioned at /var/lib/minions/certs/{domain}/
pub struct AcmeClient {
    store: CertStore,
}

impl AcmeClient {
    pub async fn new(
        certs_dir: impl AsRef<Path>,
        _email: &str,
        _staging: bool,
        _cf_dns_token: Option<String>,
        _challenges: Arc<DashMap<String, String>>,
    ) -> Result<Self> {
        let store = CertStore::new(certs_dir);
        info!("ACME client initialized (manual cert mode - auto-provisioning not yet implemented)");
        warn!("Place certificates manually at /var/lib/minions/certs/{{domain}}/{{fullchain.pem,privkey.pem}}");
        Ok(Self { store })
    }

    pub async fn provision_dns01_wildcard(&self, base_domain: &str) -> Result<()> {
        let wildcard = format!("*.{}", base_domain);
        if self.store.load_cert(&wildcard)?.is_some() {
            info!(domain = %wildcard, "certificate already exists");
            Ok(())
        } else {
            anyhow::bail!(
                "Wildcard certificate for {} not found.\n\
                 Manual provisioning required for now:\n\
                 1. Obtain cert via certbot: certbot certonly --manual --preferred-challenges dns -d '*.{}'\n\
                 2. Copy fullchain.pem and privkey.pem to /var/lib/minions/certs/{}/\n\
                 3. Restart minions",
                wildcard, base_domain, wildcard
            )
        }
    }

    pub async fn provision_http01(&self, domain: &str) -> Result<()> {
        if self.store.load_cert(domain)?.is_some() {
            info!(domain, "certificate already exists");
            Ok(())
        } else {
            anyhow::bail!(
                "Certificate for {} not found.\n\
                 Manual provisioning required for now:\n\
                 1. Obtain cert via certbot: certbot certonly --standalone -d {}\n\
                 2. Copy fullchain.pem and privkey.pem to /var/lib/minions/certs/{}/\n\
                 3. Restart minions",
                domain, domain, domain
            )
        }
    }

    pub async fn renew_if_needed(&self, _domain: &str, _is_wildcard: bool) -> Result<()> {
        // Stub - no auto-renewal yet
        Ok(())
    }
}

// ── SNI Resolver ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SniResolver {
    base_domain: String,
    #[allow(dead_code)]
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    #[allow(dead_code)]
    store: CertStore,
}

impl SniResolver {
    pub fn new(base_domain: String, certs_dir: impl AsRef<Path>) -> Self {
        Self {
            base_domain,
            cache: Arc::new(DashMap::new()),
            store: CertStore::new(certs_dir),
        }
    }

    pub fn load_and_cache(&self, domain: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(cached) = self.cache.get(domain) {
            return Ok(cached.clone());
        }

        let (certs, key) = self
            .store
            .load_cert(domain)?
            .with_context(|| format!("no certificate found for {}", domain))?;

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .context("unsupported private key type")?;

        let certified_key = Arc::new(CertifiedKey::new(certs, signing_key));
        self.cache.insert(domain.to_string(), certified_key.clone());
        info!(domain, "certificate loaded and cached");
        Ok(certified_key)
    }

    pub fn reload(&self, domain: &str) -> Result<()> {
        self.cache.remove(domain);
        self.load_and_cache(domain)?;
        Ok(())
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;

        // Try exact match first (custom domains).
        if let Ok(cert) = self.load_and_cache(sni) {
            return Some(cert);
        }

        // Fall back to wildcard for *.base_domain subdomains or the apex itself.
        // Cloudflare Full mode terminates TLS at the edge, so using the wildcard
        // cert for the apex is acceptable — the browser never sees it directly.
        let is_our_subdomain = sni
            .strip_suffix(&format!(".{}", self.base_domain))
            .map_or(false, |sub| !sub.contains('.'));
        let is_apex = sni == self.base_domain;

        if is_our_subdomain || is_apex {
            let wildcard = format!("*.{}", self.base_domain);
            if let Ok(cert) = self.load_and_cache(&wildcard) {
                return Some(cert);
            }
        }

        warn!(sni, "no certificate found");
        None
    }
}

// ── Renewal Task (stub) ───────────────────────────────────────────────────────

pub fn spawn_renewal_task(
    _acme: Arc<AcmeClient>,
    _sni_resolver: Arc<SniResolver>,
    _base_domain: String,
    _db_path: String,
) {
    // Stub - no automatic renewal yet
    info!("Certificate renewal task not yet implemented (manual renewal required)");
}
