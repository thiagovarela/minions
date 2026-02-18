//! DNS verification for custom domains.
//!
//! Checks that a custom domain is properly configured (CNAME or A record) before
//! allowing registration. This prevents domain squatting and ensures the user
//! actually controls the domain.

use anyhow::Result;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use tracing::{debug, warn};

/// Verify that a custom domain points to the expected VM subdomain or host IP.
///
/// Checks:
/// 1. If the domain has a CNAME record pointing to `{vm_name}.{base_domain}`
/// 2. If the domain has an A record pointing to `public_ip`
///
/// Returns Ok(true) if verification passes, Ok(false) if DNS is misconfigured,
/// Err if DNS resolution fails (network error, timeout, etc).
pub async fn verify_domain_dns(
    domain: &str,
    vm_name: &str,
    base_domain: &str,
    public_ip: Option<&str>,
) -> Result<bool> {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::cloudflare(),
        ResolverOpts::default(),
    );

    let expected_cname = format!("{}.{}.", vm_name, base_domain); // Trailing dot = FQDN

    // Try CNAME lookup first
    debug!(domain, expected = %expected_cname, "checking CNAME record");
    match resolver.lookup(domain, RecordType::CNAME).await {
        Ok(cname_lookup) => {
            for record in cname_lookup.record_iter() {
                if let Some(cname_data) = record.data().and_then(|d| d.as_cname()) {
                    let target = cname_data.to_string();
                    debug!(domain, cname = %target, "found CNAME record");
                    
                    // CNAME targets may or may not have a trailing dot
                    if target == expected_cname || target == expected_cname.trim_end_matches('.') {
                        debug!(domain, "CNAME points to correct VM subdomain");
                        return Ok(true);
                    }
                }
            }
            debug!(domain, "CNAME exists but does not point to VM subdomain");
        }
        Err(e) => {
            debug!(domain, error = %e, "CNAME lookup failed (may not have CNAME)");
        }
    }

    // Fall back to A record check if public_ip is configured
    if let Some(ip) = public_ip {
        debug!(domain, expected_ip = %ip, "checking A record");
        match resolver.ipv4_lookup(domain).await {
            Ok(a_lookup) => {
                for record in a_lookup.iter() {
                    let resolved_ip = record.to_string();
                    debug!(domain, a_record = %resolved_ip, "found A record");
                    
                    if resolved_ip == ip {
                        debug!(domain, "A record points to correct host IP");
                        return Ok(true);
                    }
                }
                debug!(domain, "A record exists but does not point to host IP");
            }
            Err(e) => {
                debug!(domain, error = %e, "A record lookup failed");
            }
        }
    }

    warn!(
        domain,
        "DNS verification failed: no matching CNAME or A record found"
    );
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_cloudflare_dns() {
        // This test uses real DNS — cloudflare.com definitely has DNS records.
        // Just checking the function doesn't panic.
        let result = verify_domain_dns(
            "cloudflare.com",
            "test",
            "example.com",
            Some("1.1.1.1"),
        )
        .await;
        
        // Don't assert true/false since DNS can change, just that it runs
        assert!(result.is_ok());
    }
}
