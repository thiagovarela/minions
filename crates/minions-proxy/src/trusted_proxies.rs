//! Trusted-proxy awareness for client-IP headers.
//!
//! Headers like `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` are
//! trivially spoofable, so they must only be honored when the direct peer is a
//! trusted proxy (e.g. a local `cloudflared` daemon terminating a Cloudflare
//! Tunnel). Configure via environment:
//!
//! ```text
//! MINIONS_TRUSTED_PROXIES=127.0.0.1,::1        # default: localhost only
//! MINIONS_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8 # plain IPs and/or CIDRs
//! MINIONS_TRUSTED_PROXIES=none                 # never trust proxy headers
//! ```
//!
//! When the peer is not trusted, all forwarding headers are ignored: the peer
//! IP is used as the client IP and the request is classified as `direct`.

use std::net::IpAddr;

use ipnet::IpNet;

/// Set of networks whose forwarding headers are trusted.
#[derive(Clone, Debug)]
pub struct TrustedProxies {
    networks: Vec<IpNet>,
}

impl Default for TrustedProxies {
    /// Localhost only — safe default for a local `cloudflared` (or any local
    /// ingress proxy) and for direct exposure (headers from remote peers are
    /// never trusted).
    fn default() -> Self {
        Self {
            networks: vec![
                "127.0.0.0/8".parse().expect("valid loopback v4 CIDR"),
                "::1/128".parse().expect("valid loopback v6 CIDR"),
            ],
        }
    }
}

impl TrustedProxies {
    /// Load from `MINIONS_TRUSTED_PROXIES` (comma-separated IPs or CIDRs).
    ///
    /// - unset / empty → localhost-only default
    /// - `none` → trust no one (ignore all forwarding headers)
    /// - invalid entries are skipped with a warning
    pub fn from_env() -> Self {
        let raw = std::env::var("MINIONS_TRUSTED_PROXIES").unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Self::default();
        }
        if raw.eq_ignore_ascii_case("none") {
            return Self { networks: vec![] };
        }
        let networks = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|entry| match parse_entry(entry) {
                Ok(net) => Some(net),
                Err(e) => {
                    tracing::warn!(entry, error = %e, "ignoring invalid MINIONS_TRUSTED_PROXIES entry");
                    None
                }
            })
            .collect();
        Self { networks }
    }

    /// Returns true if `ip` belongs to a trusted proxy network.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|n| n.contains(&ip))
    }

    /// Number of configured trusted networks (for startup logging).
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Returns true if no networks are trusted (`MINIONS_TRUSTED_PROXIES=none`).
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

/// Parse a single entry: bare IP (becomes a /32 or /128 host route) or CIDR.
fn parse_entry(entry: &str) -> Result<IpNet, String> {
    if entry.contains('/') {
        entry.parse::<IpNet>().map_err(|e| e.to_string())
    } else {
        entry
            .parse::<IpAddr>()
            .map(IpNet::from)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_trusts_localhost_only() {
        let t = TrustedProxies::default();
        assert!(t.is_trusted(v4("127.0.0.1")));
        assert!(t.is_trusted(v4("127.0.0.7")));
        assert!(t.is_trusted("::1".parse().unwrap()));
        assert!(!t.is_trusted(v4("8.8.8.8")));
        assert!(!t.is_trusted(v4("10.0.0.1")));
    }

    #[test]
    fn parses_ips_and_cidrs() {
        let t = TrustedProxies {
            networks: vec![
                parse_entry("10.0.0.5").unwrap(),
                parse_entry("192.168.0.0/16").unwrap(),
                parse_entry("fd00::/8").unwrap(),
            ],
        };
        assert!(t.is_trusted(v4("10.0.0.5")));
        assert!(!t.is_trusted(v4("10.0.0.6")));
        assert!(t.is_trusted(v4("192.168.1.1")));
        assert!(t.is_trusted("fd00::1234".parse().unwrap()));
        assert!(!t.is_trusted(v4("172.16.0.1")));
        assert!(!t.is_trusted("::1".parse().unwrap()));
    }

    #[test]
    fn empty_env_uses_default() {
        // Simulates unset/empty var → localhost default.
        let raw = "";
        let parsed = if raw.is_empty() {
            TrustedProxies::default()
        } else {
            unreachable!()
        };
        assert!(parsed.is_trusted(v4("127.0.0.1")));
        assert!(!parsed.is_trusted(v4("1.2.3.4")));
    }

    #[test]
    fn invalid_entries_are_skipped() {
        assert!(parse_entry("not-an-ip").is_err());
        assert!(parse_entry("10.0.0.0/33").is_err());
        // A valid entry still parses alongside junk.
        assert!(parse_entry("10.0.0.0/8").is_ok());
    }
}
