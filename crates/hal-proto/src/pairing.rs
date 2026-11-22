//! Out-of-band pairing bundle contract and peer credential helpers shared
//! between `halctl` (host enrollment) and `hal-bridge` (laptop pairing).

use crate::canonical::hex_encode;
use crate::token::is_valid_path_pattern;
use crate::types::CapabilityToken;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;

/// Current schema version for [`PairingBundle`].
pub const PAIRING_BUNDLE_VERSION: u32 = 1;

/// Bootstrap bundle generated on the `HAL Core` host by `halctl peer enroll` and
/// consumed on the laptop by `hal-bridge pair --bundle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingBundle {
    pub version: u32,
    pub agent_id: String,
    pub gateway_addr: String,
    pub cert_sha256: String,
    pub peer_proof_key: String,
    pub cap_token: CapabilityToken,
    pub issued_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_peer_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_allowed_ips: Option<Vec<String>>,
}

impl PairingBundle {
    /// Validates structural and cryptographic invariants of this pairing bundle.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PAIRING_BUNDLE_VERSION {
            return Err(format!(
                "unsupported pairing bundle version {}",
                self.version
            ));
        }
        if !is_valid_agent_id(&self.agent_id) {
            return Err(format!("invalid agent_id '{}'", self.agent_id));
        }
        let gateway = self.gateway_addr.trim();
        if gateway.parse::<SocketAddr>().is_err() {
            return Err(format!(
                "invalid gateway_addr '{}': expected <ip>:<port>",
                self.gateway_addr
            ));
        }
        if !is_valid_hex_64(&self.cert_sha256) {
            return Err(
                "cert_sha256 must be 64 lowercase hexadecimal characters".to_string(),
            );
        }
        if self.peer_proof_key.trim().is_empty() {
            return Err("peer_proof_key cannot be empty".to_string());
        }
        if self.cap_token.subject_agent_id != self.agent_id {
            return Err(format!(
                "capability token subject '{}' does not match bundle agent_id '{}'",
                self.cap_token.subject_agent_id, self.agent_id
            ));
        }
        if self.cap_token.path_patterns.is_empty() {
            return Err("capability token must allow at least one path pattern".to_string());
        }
        for pat in &self.cap_token.path_patterns {
            if !is_valid_path_pattern(pat) {
                return Err(format!("invalid capability path pattern '{pat}'"));
            }
        }
        if self.cap_token.allowed_ops.is_empty() {
            return Err("capability token must allow at least one operation".to_string());
        }
        if self.cap_token.hmac_sha256.trim().is_empty() {
            return Err("capability token signature cannot be empty".to_string());
        }
        Ok(())
    }
}

/// Validates an agent identifier: starts with ASCII alphanumeric, followed by up
/// to 63 ASCII alphanumeric, `.`, `_`, or `-` characters.
#[must_use]
pub fn is_valid_agent_id(agent_id: &str) -> bool {
    !agent_id.is_empty()
        && agent_id.len() <= 64
        && agent_id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && agent_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Validates a 64-character lowercase hexadecimal digest string.
#[must_use]
pub fn is_valid_hex_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates a POSIX shell / systemd / rc.d environment variable identifier.
#[must_use]
pub fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(idx, b)| {
            if idx == 0 {
                b.is_ascii_alphabetic() || b == b'_'
            } else {
                b.is_ascii_alphanumeric() || b == b'_'
            }
        })
}

/// Deterministically derives the `HAL_PEER_KEY_<AGENT_UPPER>` environment variable
/// name for a peer ID, converting non-alphanumeric characters to `_`.
#[must_use]
pub fn env_var_name_for_peer(agent_id: &str) -> String {
    let mut out = String::from("HAL_PEER_KEY_");
    for b in agent_id.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push((b as char).to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Reads `num_bytes` cryptographically random bytes from `/dev/urandom` and
/// encodes them as lowercase hexadecimal (`2 * num_bytes` chars).
pub fn random_hex_bytes(num_bytes: usize) -> Result<String, std::io::Error> {
    if num_bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "num_bytes must be greater than zero",
        ));
    }
    let mut file = File::open("/dev/urandom")?;
    let mut buf = vec![0u8; num_bytes];
    file.read_exact(&mut buf)?;
    Ok(hex_encode(&buf))
}

/// Parses a positive duration specification (`500ms`, `10s`, `5m`, `24h`, `7d`)
/// into milliseconds.
pub fn parse_duration_ms(spec: &str) -> Result<u64, String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    let (digits, mult) = if let Some(num) = s.strip_suffix("ms") {
        (num, 1_u64)
    } else if let Some(num) = s.strip_suffix('s') {
        (num, 1_000_u64)
    } else if let Some(num) = s.strip_suffix('m') {
        (num, 60_000_u64)
    } else if let Some(num) = s.strip_suffix('h') {
        (num, 3_600_000_u64)
    } else if let Some(num) = s.strip_suffix('d') {
        (num, 86_400_000_u64)
    } else {
        return Err(format!(
            "invalid duration '{spec}': expected suffix ms, s, m, h, or d"
        ));
    };

    if digits.trim().is_empty() {
        return Err(format!("missing numeric value in duration '{spec}'"));
    }
    let val: u64 = digits
        .trim()
        .parse()
        .map_err(|e| format!("invalid duration number in '{spec}': {e}"))?;
    if val == 0 {
        return Err("duration must be greater than zero".to_string());
    }
    val.checked_mul(mult)
        .ok_or_else(|| format!("duration '{spec}' overflows u64 milliseconds"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::sign_token;
    use crate::types::RiskTier;

    #[test]
    fn env_var_name_mapping_and_validation() {
        assert_eq!(
            env_var_name_for_peer("remote-laptop-01"),
            "HAL_PEER_KEY_REMOTE_LAPTOP_01"
        );
        assert_eq!(
            env_var_name_for_peer("dev.box_a"),
            "HAL_PEER_KEY_DEV_BOX_A"
        );
        assert!(is_valid_env_name("HAL_TOKEN_SECRET"));
        assert!(!is_valid_env_name("1ABC"));
        assert!(!is_valid_env_name("BAD-NAME"));
        assert!(is_valid_agent_id("remote-laptop-01"));
        assert!(!is_valid_agent_id("-bad"));
        assert!(!is_valid_agent_id("bad/path"));
    }

    #[test]
    fn parse_duration_ms_units_and_rejects_invalid() {
        assert_eq!(parse_duration_ms("500ms").unwrap(), 500);
        assert_eq!(parse_duration_ms("10s").unwrap(), 10_000);
        assert_eq!(parse_duration_ms("5m").unwrap(), 300_000);
        assert_eq!(parse_duration_ms("24h").unwrap(), 86_400_000);
        assert_eq!(parse_duration_ms("7d").unwrap(), 604_800_000);
        assert!(parse_duration_ms("0s").is_err());
        assert!(parse_duration_ms("10").is_err());
        assert!(parse_duration_ms("h").is_err());
        assert!(parse_duration_ms("").is_err());
    }

    #[test]
    fn random_hex_bytes_are_unique_and_sized() {
        let a = random_hex_bytes(32).unwrap();
        let b = random_hex_bytes(32).unwrap();
        assert!(is_valid_hex_64(&a));
        assert!(is_valid_hex_64(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn pairing_bundle_roundtrip_and_validation() {
        let mut tok = CapabilityToken {
            token_id: "tok-pair-1".to_string(),
            subject_agent_id: "remote-laptop-01".to_string(),
            path_patterns: vec!["/workspace/**".to_string()],
            allowed_ops: vec!["read_file".to_string()],
            max_risk_tier: RiskTier::L1ReversibleCow,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: 9_999_999_999_999,
            rate_limit_per_min: 60,
            token_budget: Some(1_000),
            hmac_sha256: String::new(),
        };
        sign_token(&mut tok, b"test-secret");

        let bundle = PairingBundle {
            version: PAIRING_BUNDLE_VERSION,
            agent_id: "remote-laptop-01".to_string(),
            gateway_addr: "10.99.0.1:9443".to_string(),
            cert_sha256: "a".repeat(64),
            peer_proof_key: "b".repeat(64),
            cap_token: tok,
            issued_at_ms: 1_700_000_000_000,
            wg_peer_pubkey: Some("wg-pub-key".to_string()),
            wg_allowed_ips: Some(vec!["10.99.0.10/32".to_string()]),
        };
        bundle.validate().unwrap();

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let decoded: PairingBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, bundle);

        let mut bad_subject = bundle.clone();
        bad_subject.cap_token.subject_agent_id = "other-agent".to_string();
        assert!(bad_subject.validate().is_err());

        let mut bad_hex = bundle.clone();
        bad_hex.cert_sha256 = "not-hex".to_string();
        assert!(bad_hex.validate().is_err());

        let mut bad_addr = bundle;
        bad_addr.gateway_addr = "not-an-addr".to_string();
        assert!(bad_addr.validate().is_err());
    }
}
