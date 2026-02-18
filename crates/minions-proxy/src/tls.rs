//! TLS certificate management with Let's Encrypt ACME.
//!
//! Supports two challenge types:
//! - **HTTP-01** for custom domains (e.g. custom.example.com)
//! - **DNS-01** for wildcard certificates (e.g. *.miniclankers.com)
//!
//! Certificates are stored at `/var/lib/minions/certs/{domain}/` with:
//! - `fullchain.pem` — certificate + intermediate chain
//! - `privkey.pem` — private key
//!
//! Automatic renewal runs every 12 hours, renewing certs expiring within 30 days.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// ── Constants ─────────────────────────────────────────────────────────────────

/// ACME account file (stores account private key + URL).
const ACME_ACCOUNT_FILE: &str = "acme_account.json";

/// Days before expiry to trigger renewal.
const RENEWAL_THRESHOLD_DAYS: i64 = 30;

/// HTTP-01 challenge response map (token → key authorization).
pub type ChallengeMap = Arc<DashMap<String, String>>;

// ── Certificate Storage ───────────────────────────────────────────────────────

pub struct CertStore {
    certs_dir: PathBuf,
}

impl CertStore {
    pub fn new(certs_dir: impl AsRef<Path>) -> Self {
        Self {
            certs_dir: certs_dir.as_ref().to_path_buf(),
        }
    }

    /// Domain-specific directory: `/var/lib/minions/certs/{domain}/`
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

    /// Store certificate chain + private key to disk.
    pub fn store_cert(&self, domain: &str, fullchain_pem: &[u8], privkey_pem: &[u8]) -> Result<()> {
        let dir = self.domain_dir(domain);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create {}", dir.display()))?;

        std::fs::write(dir.join("fullchain.pem"), fullchain_pem)
            .context("write fullchain.pem")?;
        std::fs::write(dir.join("privkey.pem"), privkey_pem)
            .context("write privkey.pem")?;

        info!(domain, "certificate stored");
        Ok(())
    }

    /// Check if a certificate needs renewal (expires within 30 days).
    pub fn needs_renewal(&self, domain: &str) -> bool {
        match self.load_cert(domain) {
            Ok(Some((certs, _))) => {
                if let Some(cert) = certs.first() {
                    if let Ok(parsed) = x509_parser::parse_x509_certificate(&cert) {
                        let validity = parsed.1.validity();
                        let not_after = validity.not_after.timestamp();
                        let now = chrono::Utc::now().timestamp();
                        let days_left = (not_after - now) / 86400;
                        return days_left < RENEWAL_THRESHOLD_DAYS;
                    }
                }
                true // Can't parse cert → assume it needs renewal
            }
            _ => true, // No cert or error loading → needs renewal
        }
    }

    /// List all managed domains with their expiry dates.
    pub fn list_managed_domains(&self) -> Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> {
        let mut domains = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.certs_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(domain) = entry.file_name().to_str() {
                        let expiry = self.get_cert_expiry(domain);
                        domains.push((domain.to_string(), expiry));
                    }
                }
            }
        }
        domains
    }

    fn get_cert_expiry(&self, domain: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let (certs, _) = self.load_cert(domain).ok()??;
        let cert = certs.first()?;
        let parsed = x509_parser::parse_x509_certificate(cert).ok()?.1;
        let not_after = parsed.validity().not_after.timestamp();
        Some(chrono::DateTime::from_timestamp(not_after, 0)?)
    }
}

// ── ACME Account Management ───────────────────────────────────────────────────

pub struct AcmeClient {
    account: Account,
    store: CertStore,
    /// Cloudflare DNS API token (for DNS-01 challenges).
    cf_dns_token: Option<String>,
    /// Challenge response map (for HTTP-01 challenges).
    challenges: ChallengeMap,
}

impl AcmeClient {
    /// Load or create ACME account.
    pub async fn new(
        certs_dir: impl AsRef<Path>,
        email: &str,
        staging: bool,
        cf_dns_token: Option<String>,
        challenges: ChallengeMap,
    ) -> Result<Self> {
        let store = CertStore::new(certs_dir.as_ref());
        let account_path = certs_dir.as_ref().join(ACME_ACCOUNT_FILE);

        let account = if account_path.exists() {
            info!("loading ACME account from {}", account_path.display());
            let json = std::fs::read_to_string(&account_path)?;
            serde_json::from_str(&json).context("parse ACME account")?
        } else {
            info!("creating new ACME account with email: {}", email);
            let server_url = if staging {
                LetsEncrypt::Staging.url()
            } else {
                LetsEncrypt::Production.url()
            };
            let (account, _credentials) = Account::create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                server_url,
                None,
            )
            .await
            .context("create ACME account")?;

            let json = serde_json::to_string_pretty(&account)?;
            std::fs::write(&account_path, json)?;
            info!("ACME account saved to {}", account_path.display());
            account
        };

        Ok(Self {
            account,
            store,
            cf_dns_token,
            challenges,
        })
    }

    /// Provision a certificate via HTTP-01 challenge (for custom domains).
    pub async fn provision_http01(&self, domain: &str) -> Result<()> {
        info!(domain, "provisioning certificate via HTTP-01");

        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(domain.to_string())],
            })
            .await
            .context("create ACME order")?;

        let authorizations = order.authorizations().await?;
        let authorization = &authorizations[0];

        let challenge = authorization
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .context("no HTTP-01 challenge found")?;

        let key_auth = order.key_authorization(challenge);
        let token = challenge.token.clone();

        // Store challenge response in shared map (port 80 handler serves it).
        self.challenges.insert(token.clone(), key_auth.as_str().to_string());

        // Tell ACME server to validate.
        order.set_challenge_ready(&challenge.url).await?;

        // Wait for validation (poll every 2 seconds, max 2 minutes).
        for _ in 0..60 {
            sleep(Duration::from_secs(2)).await;
            let auth = order.refresh_authorization(&authorization.url).await?;
            match auth.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Invalid => {
                    self.challenges.remove(&token);
                    anyhow::bail!("HTTP-01 challenge failed for {}", domain);
                }
                _ => continue,
            }
        }

        self.challenges.remove(&token);

        // Finalize order (generate CSR, submit, download cert).
        self.finalize_order(domain, &mut order).await?;
        Ok(())
    }

    /// Provision a wildcard certificate via DNS-01 challenge (requires Cloudflare DNS API).
    pub async fn provision_dns01_wildcard(&self, base_domain: &str) -> Result<()> {
        let wildcard_domain = format!("*.{}", base_domain);
        info!(wildcard_domain, "provisioning wildcard certificate via DNS-01");

        let cf_token = self
            .cf_dns_token
            .as_ref()
            .context("DNS-01 requires MINIONS_CF_DNS_TOKEN env var")?;

        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(wildcard_domain.clone())],
            })
            .await
            .context("create ACME order")?;

        let authorizations = order.authorizations().await?;
        let authorization = &authorizations[0];

        let challenge = authorization
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .context("no DNS-01 challenge found")?;

        let key_auth = order.key_authorization(challenge);
        let txt_value = instant_acme::dns_digest(&key_auth)?;
        let txt_record_name = format!("_acme-challenge.{}", base_domain);

        // Create TXT record via Cloudflare API.
        self.cloudflare_create_txt(cf_token, base_domain, &txt_record_name, &txt_value)
            .await?;

        // Tell ACME server to validate.
        order.set_challenge_ready(&challenge.url).await?;

        // Wait for validation.
        for _ in 0..60 {
            sleep(Duration::from_secs(5)).await;
            let auth = order.refresh_authorization(&authorization.url).await?;
            match auth.status {
                AuthorizationStatus::Valid => break,
                AuthorizationStatus::Invalid => {
                    // Clean up TXT record before bailing.
                    let _ = self
                        .cloudflare_delete_txt(cf_token, base_domain, &txt_record_name)
                        .await;
                    anyhow::bail!("DNS-01 challenge failed for {}", wildcard_domain);
                }
                _ => continue,
            }
        }

        // Clean up TXT record.
        self.cloudflare_delete_txt(cf_token, base_domain, &txt_record_name)
            .await?;

        // Finalize order.
        self.finalize_order(&wildcard_domain, &mut order).await?;
        Ok(())
    }

    /// Finalize ACME order: generate CSR, submit, download cert, store to disk.
    async fn finalize_order(&self, domain: &str, order: &mut instant_acme::Order) -> Result<()> {
        // Generate CSR.
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        let cert = Certificate::from_params(params)?;
        let csr = cert.serialize_request_der()?;

        // Submit CSR.
        order.finalize(&csr).await?;

        // Poll for cert (max 2 minutes).
        for _ in 0..60 {
            sleep(Duration::from_secs(2)).await;
            let state = order.refresh().await?;
            if let OrderStatus::Valid = state.status {
                break;
            }
        }

        // Download cert.
        let cert_pem = order
            .certificate()
            .await?
            .context("order valid but no certificate available")?;

        let privkey_pem = cert.serialize_private_key_pem();

        // Store to disk.
        self.store.store_cert(domain, cert_pem.as_bytes(), privkey_pem.as_bytes())?;
        Ok(())
    }

    /// Create a TXT record via Cloudflare DNS API.
    async fn cloudflare_create_txt(
        &self,
        token: &str,
        base_domain: &str,
        record_name: &str,
        value: &str,
    ) -> Result<()> {
        let zone_id = self.cloudflare_get_zone_id(token, base_domain).await?;
        let client = reqwest::Client::new();

        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp = client
            .post(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                zone_id
            ))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            anyhow::bail!("Cloudflare DNS API error: {}", text);
        }

        info!(record_name, value, "TXT record created");
        Ok(())
    }

    /// Delete a TXT record via Cloudflare DNS API.
    async fn cloudflare_delete_txt(
        &self,
        token: &str,
        base_domain: &str,
        record_name: &str,
    ) -> Result<()> {
        let zone_id = self.cloudflare_get_zone_id(token, base_domain).await?;
        let record_id = self.cloudflare_get_txt_record_id(token, &zone_id, record_name).await?;

        let client = reqwest::Client::new();
        let resp = client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                zone_id, record_id
            ))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            let text = resp.text().await?;
            warn!("failed to delete TXT record {}: {}", record_name, text);
        } else {
            info!(record_name, "TXT record deleted");
        }

        Ok(())
    }

    /// Get Cloudflare Zone ID for a domain.
    async fn cloudflare_get_zone_id(&self, token: &str, domain: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let resp = client
            .get("https://api.cloudflare.com/client/v4/zones")
            .bearer_auth(token)
            .query(&[("name", domain)])
            .send()
            .await?;

        let json: serde_json::Value = resp.json().await?;
        let zone_id = json["result"][0]["id"]
            .as_str()
            .context("no zone found for domain")?
            .to_string();

        Ok(zone_id)
    }

    /// Get Cloudflare DNS record ID for a TXT record.
    async fn cloudflare_get_txt_record_id(
        &self,
        token: &str,
        zone_id: &str,
        record_name: &str,
    ) -> Result<String> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
                zone_id
            ))
            .bearer_auth(token)
            .query(&[("type", "TXT"), ("name", record_name)])
            .send()
            .await?;

        let json: serde_json::Value = resp.json().await?;
        let record_id = json["result"][0]["id"]
            .as_str()
            .context("TXT record not found")?
            .to_string();

        Ok(record_id)
    }

    /// Check if a certificate needs renewal and renew if so.
    pub async fn renew_if_needed(&self, domain: &str, is_wildcard: bool) -> Result<()> {
        if !self.store.needs_renewal(domain) {
            debug!(domain, "certificate does not need renewal yet");
            return Ok(());
        }

        info!(domain, "certificate needs renewal");
        if is_wildcard {
            self.provision_dns01_wildcard(domain.trim_start_matches("*.")).await
        } else {
            self.provision_http01(domain).await
        }
    }
}

// ── SNI-based Certificate Resolver ────────────────────────────────────────────

pub struct SniResolver {
    /// Base domain (e.g. "miniclankers.com").
    base_domain: String,
    /// In-memory cert cache: domain → CertifiedKey.
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    /// Certificate storage.
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

    /// Load a certificate from disk and cache it.
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

    /// Reload a certificate from disk (for renewal).
    pub fn reload(&self, domain: &str) -> Result<()> {
        self.cache.remove(domain);
        self.load_and_cache(domain)?;
        Ok(())
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        debug!(sni, "SNI-based certificate resolution");

        // Try exact match first (custom domains).
        if let Ok(cert) = self.load_and_cache(sni) {
            return Some(cert);
        }

        // Fall back to wildcard if it's a subdomain of base_domain.
        if let Some(subdomain) = sni.strip_suffix(&format!(".{}", self.base_domain)) {
            if !subdomain.contains('.') {
                // Single-level subdomain → use wildcard.
                let wildcard = format!("*.{}", self.base_domain);
                if let Ok(cert) = self.load_and_cache(&wildcard) {
                    return Some(cert);
                }
            }
        }

        // No matching cert.
        warn!(sni, "no certificate found");
        None
    }
}

// ── Renewal Task ──────────────────────────────────────────────────────────────

/// Spawn a background task that renews certificates every 12 hours.
pub fn spawn_renewal_task(
    acme: Arc<AcmeClient>,
    sni_resolver: Arc<SniResolver>,
    base_domain: String,
    db_path: String,
) {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(12 * 3600)).await;
            info!("starting certificate renewal check");

            // Renew wildcard cert.
            let wildcard = format!("*.{}", base_domain);
            if let Err(e) = acme.renew_if_needed(&wildcard, true).await {
                error!(domain = %wildcard, "renewal failed: {:#}", e);
            } else if let Err(e) = sni_resolver.reload(&wildcard) {
                error!(domain = %wildcard, "reload failed: {:#}", e);
            }

            // Renew custom domain certs.
            let domains = match crate::db::open(&db_path) {
                Ok(conn) => match crate::db::list_all_verified_domains(&conn) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("failed to list domains: {:#}", e);
                        continue;
                    }
                },
                Err(e) => {
                    error!("failed to open db: {:#}", e);
                    continue;
                }
            };

            for domain in domains {
                if let Err(e) = acme.renew_if_needed(&domain, false).await {
                    error!(domain, "renewal failed: {:#}", e);
                } else if let Err(e) = sni_resolver.reload(&domain) {
                    error!(domain, "reload failed: {:#}", e);
                }
            }

            info!("certificate renewal check complete");
        }
    });
}
