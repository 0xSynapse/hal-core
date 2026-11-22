use hal_proto::RiskTier;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Parsed IPv4 CIDR subnet used to restrict remote agent ingress sources (e.g. WireGuard peers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: u32,
    mask: u32,
    raw: String,
}

impl Ipv4Cidr {
    pub fn parse(input: &str) -> Result<Self, GatewayConfigError> {
        let trimmed = input.trim();
        let (ip_part, prefix_part) = trimmed.split_once('/').ok_or_else(|| {
            GatewayConfigError::Validation(format!("CIDR '{trimmed}' missing '/' prefix"))
        })?;
        let ipv4: Ipv4Addr = ip_part.parse().map_err(|e| {
            GatewayConfigError::Validation(format!("invalid IPv4 in CIDR '{trimmed}': {e}"))
        })?;
        let prefix: u32 = prefix_part.parse().map_err(|e| {
            GatewayConfigError::Validation(format!("invalid prefix in CIDR '{trimmed}': {e}"))
        })?;
        if prefix > 32 {
            return Err(GatewayConfigError::Validation(format!(
                "IPv4 CIDR prefix '{prefix}' exceeds 32"
            )));
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = u32::from(ipv4) & mask;
        Ok(Self {
            network,
            mask,
            raw: trimmed.to_string(),
        })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ipv4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        ipv4.is_some_and(|v4| (u32::from(v4) & self.mask) == self.network)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Authorized remote agent peer configuration loaded from `gateway-peers.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemotePeerRule {
    pub agent_id: String,
    pub cert_sha256: String,
    pub allowed_cidrs: Vec<Ipv4Cidr>,
    pub max_risk_tier: RiskTier,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RawPeerRule {
    agent_id: String,
    cert_sha256: String,
    allowed_cidrs: Vec<String>,
    max_risk_tier: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct RawGatewayConfig {
    version: u32,
    default_policy: String,
    #[serde(default = "default_true")]
    require_cert_proof: bool,
    #[serde(default)]
    peers: Vec<RawPeerRule>,
}

/// Default-deny remote gateway allowlist configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub version: u32,
    pub default_policy: String,
    pub require_cert_proof: bool,
    pub peers: Vec<RemotePeerRule>,
}

#[derive(Debug)]
pub enum GatewayConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Validation(String),
}

impl fmt::Display for GatewayConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read gateway config: {e}"),
            Self::Toml(e) => write!(f, "invalid gateway config TOML: {e}"),
            Self::Validation(msg) => write!(f, "gateway config validation failed: {msg}"),
        }
    }
}

impl std::error::Error for GatewayConfigError {}

impl From<std::io::Error> for GatewayConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for GatewayConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl GatewayConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, GatewayConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, GatewayConfigError> {
        let raw: RawGatewayConfig = toml::from_str(toml_str)?;
        if raw.version != 1 {
            return Err(GatewayConfigError::Validation(format!(
                "unsupported gateway config version {}",
                raw.version
            )));
        }
        if raw.default_policy != "deny" {
            return Err(GatewayConfigError::Validation(format!(
                "gateway default_policy must be 'deny', got '{}'",
                raw.default_policy
            )));
        }

        let mut seen_agents = BTreeSet::new();
        let mut seen_certs = BTreeSet::new();
        let mut peers = Vec::with_capacity(raw.peers.len());

        for p in raw.peers {
            if p.agent_id.trim().is_empty() {
                return Err(GatewayConfigError::Validation(
                    "peer agent_id cannot be empty".to_string(),
                ));
            }
            if !seen_agents.insert(p.agent_id.clone()) {
                return Err(GatewayConfigError::Validation(format!(
                    "duplicate peer agent_id '{}'",
                    p.agent_id
                )));
            }
            if p.cert_sha256.len() != 64
                || !p
                    .cert_sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(GatewayConfigError::Validation(format!(
                    "peer '{}' cert_sha256 must be 64 lowercase hex characters",
                    p.agent_id
                )));
            }
            if !seen_certs.insert(p.cert_sha256.clone()) {
                return Err(GatewayConfigError::Validation(format!(
                    "duplicate cert_sha256 on peer '{}'",
                    p.agent_id
                )));
            }
            if p.allowed_cidrs.is_empty() {
                return Err(GatewayConfigError::Validation(format!(
                    "peer '{}' must specify at least one allowed_cidr",
                    p.agent_id
                )));
            }
            let mut allowed_cidrs = Vec::with_capacity(p.allowed_cidrs.len());
            for cidr in &p.allowed_cidrs {
                allowed_cidrs.push(Ipv4Cidr::parse(cidr)?);
            }
            let max_risk_tier = RiskTier::from_short_str(&p.max_risk_tier).ok_or_else(|| {
                GatewayConfigError::Validation(format!(
                    "invalid max_risk_tier '{}' on peer '{}'",
                    p.max_risk_tier, p.agent_id
                ))
            })?;

            peers.push(RemotePeerRule {
                agent_id: p.agent_id,
                cert_sha256: p.cert_sha256,
                allowed_cidrs,
                max_risk_tier,
                enabled: p.enabled,
            });
        }

        Ok(Self {
            version: raw.version,
            default_policy: raw.default_policy,
            require_cert_proof: raw.require_cert_proof,
            peers,
        })
    }

    #[must_use]
    pub fn find_by_cert(&self, cert_sha256: &str) -> Option<&RemotePeerRule> {
        self.peers
            .iter()
            .find(|p| p.enabled && p.cert_sha256 == cert_sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn repo_gateway_config_validates_and_matches_cidrs() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/gateway-peers.toml");
        let cfg = GatewayConfig::from_file(path).expect("repo gateway-peers.toml should be valid");
        assert_eq!(cfg.default_policy, "deny");
        assert_eq!(cfg.peers.len(), 2);

        let laptop = cfg
            .find_by_cert("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
        assert_eq!(laptop.agent_id, "remote-laptop-01");
        assert!(laptop
            .allowed_cidrs
            .iter()
            .any(|c| c.contains(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 42)))));
        assert!(laptop
            .allowed_cidrs
            .iter()
            .any(|c| c.contains(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)))));
        assert!(!laptop
            .allowed_cidrs
            .iter()
            .any(|c| c.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    }

    #[test]
    fn rejects_non_deny_default_and_bad_cidr() {
        let bad_default = r#"
version = 1
default_policy = "allow"
"#;
        assert!(matches!(
            GatewayConfig::from_toml_str(bad_default),
            Err(GatewayConfigError::Validation(_))
        ));

        let bad_cidr = r#"
version = 1
default_policy = "deny"

[[peers]]
agent_id = "r1"
cert_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
allowed_cidrs = ["10.0.0.1/99"]
max_risk_tier = "L0"
"#;
        assert!(matches!(
            GatewayConfig::from_toml_str(bad_cidr),
            Err(GatewayConfigError::Validation(_))
        ));
    }
}
