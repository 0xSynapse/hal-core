use hal_proto::CapabilityToken;
use serde::Deserialize;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// TOML configuration for connecting a laptop coding agent (`Aegis OS`) to `HAL Core` via `hal-gateway`.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub version: u32,
    pub gateway_addr: SocketAddr,
    pub agent_id: String,
    pub cert_sha256: String,
    pub peer_proof_key: Vec<u8>,
    pub cap_token: CapabilityToken,
    pub default_episode_id: String,
}

#[derive(Debug, Deserialize)]
struct RawBridgeConfig {
    version: u32,
    gateway_addr: String,
    agent_id: String,
    cert_sha256: String,
    peer_proof_key: Option<String>,
    peer_proof_key_env: Option<String>,
    cap_token_path: Option<PathBuf>,
    cap_token_json: Option<String>,
    default_episode_id: Option<String>,
}

#[derive(Debug)]
pub enum BridgeConfigError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Json(serde_json::Error),
    Validation(String),
}

impl fmt::Display for BridgeConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read bridge config or token: {e}"),
            Self::Toml(e) => write!(f, "invalid bridge TOML: {e}"),
            Self::Json(e) => write!(f, "invalid capability token JSON: {e}"),
            Self::Validation(msg) => write!(f, "bridge config validation failed: {msg}"),
        }
    }
}

impl std::error::Error for BridgeConfigError {}

impl From<std::io::Error> for BridgeConfigError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<toml::de::Error> for BridgeConfigError {
    fn from(value: toml::de::Error) -> Self {
        Self::Toml(value)
    }
}

impl From<serde_json::Error> for BridgeConfigError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl BridgeConfig {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, BridgeConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)?;
        let base_dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Self::from_toml_str_with_base(&raw, base_dir)
    }

    pub fn from_toml_str(toml_str: &str) -> Result<Self, BridgeConfigError> {
        Self::from_toml_str_with_base(toml_str, Path::new("."))
    }

    pub fn from_toml_str_with_base(
        toml_str: &str,
        base_dir: &Path,
    ) -> Result<Self, BridgeConfigError> {
        let raw: RawBridgeConfig = toml::from_str(toml_str)?;
        if raw.version != 1 {
            return Err(BridgeConfigError::Validation(format!(
                "unsupported bridge config version {}",
                raw.version
            )));
        }

        let gateway_addr: SocketAddr = raw.gateway_addr.trim().parse().map_err(|e| {
            BridgeConfigError::Validation(format!(
                "invalid gateway_addr '{}': {e}",
                raw.gateway_addr
            ))
        })?;

        let agent_id = raw.agent_id.trim().to_string();
        if agent_id.is_empty() {
            return Err(BridgeConfigError::Validation(
                "agent_id cannot be empty".to_string(),
            ));
        }

        let cert_sha256 = raw.cert_sha256.trim().to_string();
        if cert_sha256.len() != 64
            || !cert_sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(BridgeConfigError::Validation(
                "cert_sha256 must be 64 lowercase hex characters".to_string(),
            ));
        }

        let proof_key_str = resolve_proof_key(raw.peer_proof_key_env.as_deref(), raw.peer_proof_key)?;
        let cap_token_raw = resolve_cap_token_json(
            raw.cap_token_json,
            raw.cap_token_path.as_deref(),
            base_dir,
        )?;
        let cap_token: CapabilityToken = serde_json::from_str(&cap_token_raw)?;
        if cap_token.subject_agent_id != agent_id {
            return Err(BridgeConfigError::Validation(format!(
                "capability token subject '{}' does not match agent_id '{agent_id}'",
                cap_token.subject_agent_id
            )));
        }

        let default_episode_id = raw
            .default_episode_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "laptop-session".to_string());

        Ok(Self {
            version: raw.version,
            gateway_addr,
            agent_id,
            cert_sha256,
            peer_proof_key: proof_key_str.into_bytes(),
            cap_token,
            default_episode_id,
        })
    }
}

fn resolve_proof_key(
    env_var: Option<&str>,
    literal: Option<String>,
) -> Result<String, BridgeConfigError> {
    if let Some(name) = env_var.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(val) = std::env::var(name) {
            if !val.trim().is_empty() {
                return Ok(val);
            }
        }
    }
    if let Some(lit) = literal.filter(|s| !s.trim().is_empty()) {
        return Ok(lit);
    }
    Err(BridgeConfigError::Validation(
        "peer_proof_key or non-empty peer_proof_key_env must be configured".to_string(),
    ))
}

fn resolve_cap_token_json(
    inline_json: Option<String>,
    token_path: Option<&Path>,
    base_dir: &Path,
) -> Result<String, BridgeConfigError> {
    if let Some(json) = inline_json.filter(|s| !s.trim().is_empty()) {
        return Ok(json);
    }
    if let Some(rel_or_abs) = token_path {
        let resolved = if rel_or_abs.is_absolute() {
            rel_or_abs.to_path_buf()
        } else {
            base_dir.join(rel_or_abs)
        };
        return Ok(std::fs::read_to_string(resolved)?);
    }
    Err(BridgeConfigError::Validation(
        "either cap_token_path or cap_token_json must be provided".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::{sign_token, RiskTier};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_token(subject: &str) -> CapabilityToken {
        let mut t = CapabilityToken {
            token_id: "tok_unit".into(),
            subject_agent_id: subject.into(),
            path_patterns: vec!["/vault/**".into()],
            allowed_ops: vec!["read".into()],
            max_risk_tier: RiskTier::L0ReadOnly,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: u64::MAX,
            rate_limit_per_min: 60,
            token_budget: Some(100),
            hmac_sha256: String::new(),
        };
        sign_token(&mut t, b"unit-secret");
        t
    }

    #[test]
    fn loads_relative_token_and_validates_fields() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!("/tmp/hal_bridge_cfg_{}_{}", std::process::id(), nanos % 1_000_000_000));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("laptop.cap.json"),
            serde_json::to_string_pretty(&sample_token("remote-laptop-01")).unwrap(),
        )
        .unwrap();
        let cfg_path = dir.join("bridge.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "version = 1\ngateway_addr = \"127.0.0.1:9443\"\nagent_id = \"remote-laptop-01\"\ncert_sha256 = \"{}\"\npeer_proof_key = \"demo-key\"\ncap_token_path = \"./laptop.cap.json\"\n",
                "1".repeat(64)
            ),
        )
        .unwrap();

        let cfg = BridgeConfig::from_file(&cfg_path).unwrap();
        assert_eq!(cfg.agent_id, "remote-laptop-01");
        assert_eq!(cfg.default_episode_id, "laptop-session");
        assert_eq!(cfg.peer_proof_key, b"demo-key");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_subject_mismatch_and_bad_fingerprint() {
        let tok_json = serde_json::to_string(&sample_token("other-agent")).unwrap();
        let toml = format!(
            "version = 1\ngateway_addr = \"127.0.0.1:9443\"\nagent_id = \"remote-laptop-01\"\ncert_sha256 = \"{}\"\npeer_proof_key = \"demo-key\"\ncap_token_json = '''{tok_json}'''\n",
            "1".repeat(64)
        );
        assert!(matches!(
            BridgeConfig::from_toml_str(&toml),
            Err(BridgeConfigError::Validation(_))
        ));

        let bad_fp = format!(
            "version = 1\ngateway_addr = \"127.0.0.1:9443\"\nagent_id = \"other-agent\"\ncert_sha256 = \"not-hex\"\npeer_proof_key = \"demo-key\"\ncap_token_json = '''{tok_json}'''\n"
        );
        assert!(matches!(
            BridgeConfig::from_toml_str(&bad_fp),
            Err(BridgeConfigError::Validation(_))
        ));
    }
}
