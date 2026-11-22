//! Laptop-side pairing and capability-token renewal workflow (`hal-bridge pair`).

use crate::config::{BridgeConfig, BridgeConfigError};
use hal_proto::{is_valid_agent_id, CapabilityToken, PairingBundle};
use serde::Serialize;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Errors produced during laptop pairing or token renewal.
#[derive(Debug)]
pub enum PairError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Config(BridgeConfigError),
    Validation(String),
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error during pairing: {e}"),
            Self::Json(e) => write!(f, "invalid JSON in pairing bundle/token: {e}"),
            Self::Config(e) => write!(f, "generated bridge config validation failed: {e}"),
            Self::Validation(msg) => write!(f, "pairing validation error: {msg}"),
        }
    }
}

impl std::error::Error for PairError {}

impl From<std::io::Error> for PairError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PairError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<BridgeConfigError> for PairError {
    fn from(value: BridgeConfigError) -> Self {
        Self::Config(value)
    }
}

/// Non-secret summary emitted after pairing or token renewal completes.
#[derive(Debug, Clone, Serialize)]
pub struct PairResult {
    pub agent_id: String,
    pub gateway_addr: String,
    pub out_dir: PathBuf,
    pub config_path: PathBuf,
    pub proof_key_path: PathBuf,
    pub token_path: PathBuf,
    pub token_id: String,
    pub token_expires_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_peer_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_allowed_ips: Option<Vec<String>>,
}

fn ensure_private_dir(dir: &Path) -> Result<(), PairError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_file_0600_atomic(path: &Path, content: &[u8]) -> Result<(), PairError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("paired");
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Provisions a laptop `~/.config/hal-bridge`-style workspace from a host
/// [`PairingBundle`] JSON file (`0700` dir, `0600` proof key, `0600` token,
/// and `0600` `laptop-bridge.toml`), validating the resulting config via
/// [`BridgeConfig::from_file`].
pub fn pair_from_bundle(
    bundle_path: &Path,
    out_dir: &Path,
    gateway_override: Option<&str>,
    episode_override: Option<&str>,
) -> Result<PairResult, PairError> {
    let raw = std::fs::read_to_string(bundle_path)?;
    let mut bundle: PairingBundle = serde_json::from_str(&raw)?;
    if let Some(gw) = gateway_override.map(str::trim).filter(|s| !s.is_empty()) {
        bundle.gateway_addr = gw.to_string();
    }
    bundle.validate().map_err(PairError::Validation)?;

    ensure_private_dir(out_dir)?;

    let key_filename = format!("{}.proof.key", bundle.agent_id);
    let token_filename = format!("{}.cap.json", bundle.agent_id);
    let proof_key_path = out_dir.join(&key_filename);
    let token_path = out_dir.join(&token_filename);
    let config_path = out_dir.join("laptop-bridge.toml");

    write_file_0600_atomic(&proof_key_path, bundle.peer_proof_key.as_bytes())?;

    let mut token_json = serde_json::to_string_pretty(&bundle.cap_token)?;
    token_json.push('\n');
    write_file_0600_atomic(&token_path, token_json.as_bytes())?;

    let episode_id = episode_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("laptop-aegis-session");

    let config_toml = format!(
        "# Generated by hal-bridge pair\nversion = 1\ngateway_addr = {}\nagent_id = {}\ncert_sha256 = {}\npeer_proof_key_file = {}\ncap_token_path = {}\ndefault_episode_id = {}\n",
        toml_quote(bundle.gateway_addr.trim()),
        toml_quote(&bundle.agent_id),
        toml_quote(&bundle.cert_sha256),
        toml_quote(&format!("./{key_filename}")),
        toml_quote(&format!("./{token_filename}")),
        toml_quote(episode_id),
    );
    write_file_0600_atomic(&config_path, config_toml.as_bytes())?;

    let validated = BridgeConfig::from_file(&config_path)?;

    Ok(PairResult {
        agent_id: validated.agent_id,
        gateway_addr: validated.gateway_addr.to_string(),
        out_dir: out_dir.to_path_buf(),
        config_path,
        proof_key_path,
        token_path,
        token_id: validated.cap_token.token_id,
        token_expires_at_ms: validated.cap_token.expires_at_ms,
        wg_peer_pubkey: bundle.wg_peer_pubkey,
        wg_allowed_ips: bundle.wg_allowed_ips,
    })
}

/// Replaces the paired capability token JSON in `out_dir` while verifying that
/// the new token's `subject_agent_id` matches the existing `laptop-bridge.toml`.
pub fn update_paired_token(
    token_input_path: &Path,
    out_dir: &Path,
    expected_agent_id: Option<&str>,
) -> Result<PairResult, PairError> {
    let raw = std::fs::read_to_string(token_input_path)?;
    let token: CapabilityToken = serde_json::from_str(&raw)?;
    if !is_valid_agent_id(&token.subject_agent_id) {
        return Err(PairError::Validation(format!(
            "invalid capability token subject_agent_id '{}'",
            token.subject_agent_id
        )));
    }
    if token.hmac_sha256.trim().is_empty() {
        return Err(PairError::Validation(
            "capability token signature cannot be empty".to_string(),
        ));
    }
    if let Some(expected) = expected_agent_id {
        if expected != token.subject_agent_id {
            return Err(PairError::Validation(format!(
                "token subject '{}' does not match --agent-id '{expected}'",
                token.subject_agent_id
            )));
        }
    }

    let config_path = out_dir.join("laptop-bridge.toml");
    if !config_path.exists() {
        return Err(PairError::Validation(format!(
            "missing '{}' — run 'hal-bridge pair --bundle <file>' first",
            config_path.display()
        )));
    }
    let existing = BridgeConfig::from_file(&config_path)?;
    if existing.agent_id != token.subject_agent_id {
        return Err(PairError::Validation(format!(
            "renewed token subject '{}' does not match paired agent '{}'",
            token.subject_agent_id, existing.agent_id
        )));
    }

    let token_path = out_dir.join(format!("{}.cap.json", existing.agent_id));
    let proof_key_path = out_dir.join(format!("{}.proof.key", existing.agent_id));
    let mut token_json = serde_json::to_string_pretty(&token)?;
    token_json.push('\n');
    write_file_0600_atomic(&token_path, token_json.as_bytes())?;

    let validated = BridgeConfig::from_file(&config_path)?;
    Ok(PairResult {
        agent_id: validated.agent_id,
        gateway_addr: validated.gateway_addr.to_string(),
        out_dir: out_dir.to_path_buf(),
        config_path,
        proof_key_path,
        token_path,
        token_id: validated.cap_token.token_id,
        token_expires_at_ms: validated.cap_token.expires_at_ms,
        wg_peer_pubkey: None,
        wg_allowed_ips: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::{sign_token, PAIRING_BUNDLE_VERSION, RiskTier};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn sample_token(agent: &str, token_id: &str) -> CapabilityToken {
        let mut tok = CapabilityToken {
            token_id: token_id.to_string(),
            subject_agent_id: agent.to_string(),
            path_patterns: vec!["/vault/**".to_string()],
            allowed_ops: vec!["read".to_string()],
            max_risk_tier: RiskTier::L1ReversibleCow,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: 9_999_999_999_999,
            rate_limit_per_min: 60,
            token_budget: Some(1_000),
            hmac_sha256: String::new(),
        };
        sign_token(&mut tok, b"test-secret");
        tok
    }

    #[test]
    fn pair_from_bundle_and_renew_token_work_with_strict_permissions() {
        let root = std::env::temp_dir().join(format!("hal_p5c_pair_unit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out_dir = root.join("paired");
        std::fs::create_dir_all(&root).unwrap();

        let bundle_path = root.join("bundle.json");
        let bundle = PairingBundle {
            version: PAIRING_BUNDLE_VERSION,
            agent_id: "remote-laptop-01".to_string(),
            gateway_addr: "127.0.0.1:9443".to_string(),
            cert_sha256: "a".repeat(64),
            peer_proof_key: "proof-key-secret".to_string(),
            cap_token: sample_token("remote-laptop-01", "tok-initial"),
            issued_at_ms: 1_700_000_000_000,
            wg_peer_pubkey: None,
            wg_allowed_ips: Some(vec!["10.99.0.10/32".to_string()]),
        };
        std::fs::write(&bundle_path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

        let paired = pair_from_bundle(&bundle_path, &out_dir, None, None).unwrap();
        assert_eq!(paired.token_id, "tok-initial");
        assert!(paired.config_path.exists());
        assert!(paired.proof_key_path.exists());
        assert!(paired.token_path.exists());

        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&out_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&paired.proof_key_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&paired.token_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&paired.config_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // Token renewal updates paired token cleanly
        let renewed_file = root.join("renewed.cap.json");
        std::fs::write(
            &renewed_file,
            serde_json::to_string_pretty(&sample_token("remote-laptop-01", "tok-renewed")).unwrap(),
        )
        .unwrap();
        let renewed = update_paired_token(&renewed_file, &out_dir, None).unwrap();
        assert_eq!(renewed.token_id, "tok-renewed");

        // Subject mismatch must be rejected
        let wrong_file = root.join("wrong.cap.json");
        std::fs::write(
            &wrong_file,
            serde_json::to_string_pretty(&sample_token("other-agent", "tok-wrong")).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            update_paired_token(&wrong_file, &out_dir, None),
            Err(PairError::Validation(_))
        ));

        let _ = std::fs::remove_dir_all(&root);
    }
}
