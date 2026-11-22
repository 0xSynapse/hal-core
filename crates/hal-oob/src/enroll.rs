//! Host-side peer enrollment, proof-key provisioning (`0600`), pairing bundle
//! generation, and short-lived capability token minting for `halctl`.

use hal_gateway::{GatewayConfig, GatewayConfigError, Ipv4Cidr, RemotePeerRule};
use hal_proto::{
    env_var_name_for_peer, is_valid_agent_id, is_valid_env_name, is_valid_hex_64,
    is_valid_path_pattern, random_hex_bytes, sign_token, CapabilityToken, PairingBundle, RiskTier,
    PAIRING_BUNDLE_VERSION,
};
use serde::Serialize;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Errors produced during peer enrollment or capability token minting.
#[derive(Debug)]
pub enum EnrollError {
    Io(std::io::Error),
    GatewayConfig(GatewayConfigError),
    Json(serde_json::Error),
    Validation(String),
}

impl fmt::Display for EnrollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error during peer enrollment: {e}"),
            Self::GatewayConfig(e) => write!(f, "gateway peer config error: {e}"),
            Self::Json(e) => write!(f, "JSON serialization error: {e}"),
            Self::Validation(msg) => write!(f, "enrollment validation error: {msg}"),
        }
    }
}

impl std::error::Error for EnrollError {}

impl From<std::io::Error> for EnrollError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<GatewayConfigError> for EnrollError {
    fn from(value: GatewayConfigError) -> Self {
        Self::GatewayConfig(value)
    }
}

impl From<serde_json::Error> for EnrollError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

/// Request parameters for `halctl peer enroll`.
#[derive(Debug, Clone)]
pub struct PeerEnrollRequest {
    pub agent_id: String,
    pub allowed_ips: Vec<String>,
    pub gateway_addr: String,
    pub peers_config_path: PathBuf,
    pub secrets_file_path: PathBuf,
    pub bundle_out_path: PathBuf,
    pub token_secret_env: String,
    pub peer_key_env: Option<String>,
    pub cert_sha256: Option<String>,
    pub path_patterns: Vec<String>,
    pub allowed_ops: Vec<String>,
    pub max_risk_tier: RiskTier,
    pub ttl_ms: u64,
    pub rate_limit_per_min: u32,
    pub token_budget: Option<u64>,
    pub wg_pubkey: Option<String>,
    pub replace: bool,
    pub now_ms: u64,
}

/// Non-secret summary returned by `enroll_peer`. Raw proof keys and signing
/// secrets are deliberately excluded so stdout/logs cannot leak credentials.
#[derive(Debug, Clone, Serialize)]
pub struct PeerEnrollResult {
    pub agent_id: String,
    pub cert_sha256: String,
    pub peer_key_env: String,
    pub peers_config_path: PathBuf,
    pub secrets_file_path: PathBuf,
    pub bundle_out_path: PathBuf,
    pub replaced: bool,
    pub max_risk_tier: String,
    pub token_id: String,
    pub token_expires_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_peer_snippet: Option<String>,
}

/// Request parameters for `halctl token mint`.
#[derive(Debug, Clone)]
pub struct TokenMintRequest {
    pub agent_id: String,
    pub peers_config_path: PathBuf,
    pub secrets_file_path: Option<PathBuf>,
    pub token_secret_env: String,
    pub out_path: PathBuf,
    pub path_patterns: Vec<String>,
    pub allowed_ops: Vec<String>,
    pub requested_tier: RiskTier,
    pub ttl_ms: u64,
    pub rate_limit_per_min: u32,
    pub token_budget: Option<u64>,
    pub now_ms: u64,
}

/// Non-secret summary returned by `mint_token`.
#[derive(Debug, Clone, Serialize)]
pub struct TokenMintResult {
    pub agent_id: String,
    pub token_id: String,
    pub max_risk_tier: String,
    pub expires_at_ms: u64,
    pub out_path: PathBuf,
}

/// Atomically writes `content` to `path` with strict `0600` file permissions.
pub fn write_file_0600_atomic(path: &Path, content: &[u8]) -> Result<(), EnrollError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let nonce = random_hex_bytes(4)?;
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
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

/// Reads a named secret from the process environment or, if absent, from a
/// `0600` `secrets.env`-style `KEY=VALUE` file.
pub fn read_secret_from_env_or_file(
    env_name: &str,
    secrets_file: Option<&Path>,
) -> Result<Vec<u8>, EnrollError> {
    if !is_valid_env_name(env_name) {
        return Err(EnrollError::Validation(format!(
            "invalid environment variable name '{env_name}'"
        )));
    }
    if let Ok(val) = std::env::var(env_name) {
        let trimmed = val.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() {
            return Ok(trimmed.as_bytes().to_vec());
        }
    }

    let Some(path) = secrets_file else {
        return Err(EnrollError::Validation(format!(
            "signing secret env '{env_name}' is not set and no secrets file was provided"
        )));
    };
    if !path.exists() {
        return Err(EnrollError::Validation(format!(
            "signing secret env '{env_name}' is not set and secrets file '{}' does not exist",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if (mode & 0o077) != 0 {
            return Err(EnrollError::Validation(format!(
                "secrets file '{}' has overly permissive mode {:03o}; require 0600",
                path.display(),
                mode & 0o777
            )));
        }
    }

    let raw = std::fs::read_to_string(path)?;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed.strip_prefix("export ").map(str::trim).unwrap_or(trimmed);
        let Some((k, v)) = body.split_once('=') else {
            continue;
        };
        if k.trim() != env_name {
            continue;
        }
        let val = unquote_env_value(v.trim());
        if val.is_empty() {
            return Err(EnrollError::Validation(format!(
                "secret '{env_name}' in '{}' is empty",
                path.display()
            )));
        }
        return Ok(val.as_bytes().to_vec());
    }

    Err(EnrollError::Validation(format!(
        "secret '{env_name}' not found in environment or '{}'",
        path.display()
    )))
}

fn unquote_env_value(raw: &str) -> &str {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        &raw[1..raw.len() - 1]
    } else {
        raw
    }
}

/// Inserts or updates `key=value` inside a `0600` `KEY=VALUE` secrets file while
/// preserving unrelated entries and comments.
pub fn upsert_secrets_env_0600(
    secrets_path: &Path,
    key: &str,
    value: &str,
) -> Result<(), EnrollError> {
    if !is_valid_env_name(key) {
        return Err(EnrollError::Validation(format!(
            "invalid secrets env key '{key}'"
        )));
    }
    if value.trim().is_empty() || value.contains(['\n', '\r']) {
        return Err(EnrollError::Validation(format!(
            "secret value for '{key}' cannot be empty or multi-line"
        )));
    }

    let mut lines: Vec<String> = if secrets_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(secrets_path)?.permissions().mode();
            if (mode & 0o077) != 0 {
                return Err(EnrollError::Validation(format!(
                    "existing secrets file '{}' has overly permissive mode {:03o}; require 0600",
                    secrets_path.display(),
                    mode & 0o777
                )));
            }
        }
        std::fs::read_to_string(secrets_path)?
            .lines()
            .map(str::to_string)
            .collect()
    } else {
        vec!["# HAL Core secrets (mode 0600)".to_string()]
    };

    let assignment = format!("{key}={value}");
    let mut replaced = false;
    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let body = trimmed.strip_prefix("export ").map(str::trim).unwrap_or(trimmed);
        if let Some((existing_key, _)) = body.split_once('=') {
            if existing_key.trim() == key {
                *line = assignment.clone();
                replaced = true;
            }
        }
    }
    if !replaced {
        lines.push(assignment);
    }

    let mut rendered = lines.join("\n");
    rendered.push('\n');
    write_file_0600_atomic(secrets_path, rendered.as_bytes())
}

fn normalize_cidrs(raw_ips: &[String]) -> Result<Vec<Ipv4Cidr>, EnrollError> {
    if raw_ips.is_empty() {
        return Err(EnrollError::Validation(
            "at least one --ip <ipv4_or_cidr> is required".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(raw_ips.len());
    for raw in raw_ips {
        let trimmed = raw.trim();
        let with_prefix = if trimmed.contains('/') {
            trimmed.to_string()
        } else {
            format!("{trimmed}/32")
        };
        out.push(Ipv4Cidr::parse(&with_prefix)?);
    }
    Ok(out)
}

fn validate_token_scope(
    path_patterns: &[String],
    allowed_ops: &[String],
    ttl_ms: u64,
    rate_limit_per_min: u32,
) -> Result<(), EnrollError> {
    if path_patterns.is_empty() {
        return Err(EnrollError::Validation(
            "at least one capability path pattern is required".to_string(),
        ));
    }
    for pat in path_patterns {
        if !is_valid_path_pattern(pat) {
            return Err(EnrollError::Validation(format!(
                "invalid capability path pattern '{pat}'"
            )));
        }
    }
    if allowed_ops.is_empty() || allowed_ops.iter().any(|op| op.trim().is_empty()) {
        return Err(EnrollError::Validation(
            "allowed_ops must contain at least one non-empty operation".to_string(),
        ));
    }
    if ttl_ms == 0 {
        return Err(EnrollError::Validation(
            "token TTL must be greater than zero".to_string(),
        ));
    }
    if rate_limit_per_min == 0 {
        return Err(EnrollError::Validation(
            "rate_limit_per_min must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

/// Enrolls a remote Aegis OS workstation peer on the `HAL Core` host:
/// updates `gateway-peers.toml`, stores the generated proof key in `0600`
/// `secrets.env`, signs an initial [`CapabilityToken`], and writes an atomic
/// `0600` [`PairingBundle`] JSON file.
pub fn enroll_peer(req: &PeerEnrollRequest) -> Result<PeerEnrollResult, EnrollError> {
    if !is_valid_agent_id(&req.agent_id) {
        return Err(EnrollError::Validation(format!(
            "invalid agent_id '{}'",
            req.agent_id
        )));
    }
    let gateway_addr: SocketAddr = req.gateway_addr.trim().parse().map_err(|e| {
        EnrollError::Validation(format!(
            "invalid gateway_addr '{}': {e}",
            req.gateway_addr
        ))
    })?;
    let cidrs = normalize_cidrs(&req.allowed_ips)?;
    validate_token_scope(
        &req.path_patterns,
        &req.allowed_ops,
        req.ttl_ms,
        req.rate_limit_per_min,
    )?;

    let peer_key_env = req
        .peer_key_env
        .clone()
        .unwrap_or_else(|| env_var_name_for_peer(&req.agent_id));
    if !is_valid_env_name(&peer_key_env) {
        return Err(EnrollError::Validation(format!(
            "invalid --peer-key-env name '{peer_key_env}'"
        )));
    }

    let cert_sha256 = match &req.cert_sha256 {
        Some(fp) => {
            let trimmed = fp.trim().to_string();
            if !is_valid_hex_64(&trimmed) {
                return Err(EnrollError::Validation(
                    "cert_sha256 must be 64 lowercase hexadecimal characters".to_string(),
                ));
            }
            trimmed
        }
        None => random_hex_bytes(32)?,
    };

    if let Some(wg) = req.wg_pubkey.as_deref() {
        if wg.trim().is_empty() || wg.contains(['\n', '\r']) {
            return Err(EnrollError::Validation(
                "wg_pubkey cannot be empty or contain newlines".to_string(),
            ));
        }
    }

    let token_secret =
        read_secret_from_env_or_file(&req.token_secret_env, Some(&req.secrets_file_path))?;

    let mut gw_cfg = if req.peers_config_path.exists() {
        GatewayConfig::from_file(&req.peers_config_path)?
    } else {
        GatewayConfig::empty_default_deny()
    };

    let rule = RemotePeerRule {
        agent_id: req.agent_id.clone(),
        cert_sha256: cert_sha256.clone(),
        allowed_cidrs: cidrs.clone(),
        max_risk_tier: req.max_risk_tier,
        enabled: true,
    };
    let replaced = gw_cfg.upsert_peer(rule, req.replace)?;

    let peer_proof_key = random_hex_bytes(32)?;
    let token_nonce = random_hex_bytes(6)?;
    let token_expires_at_ms = req.now_ms.saturating_add(req.ttl_ms);
    let mut cap_token = CapabilityToken {
        token_id: format!("tok-{}-{token_nonce}", req.agent_id),
        subject_agent_id: req.agent_id.clone(),
        path_patterns: req.path_patterns.clone(),
        allowed_ops: req.allowed_ops.clone(),
        max_risk_tier: req.max_risk_tier,
        delegation_depth: 0,
        max_delegation_depth: 1,
        expires_at_ms: token_expires_at_ms,
        rate_limit_per_min: req.rate_limit_per_min,
        token_budget: req.token_budget,
        hmac_sha256: String::new(),
    };
    sign_token(&mut cap_token, &token_secret);

    let wg_allowed_ips: Vec<String> = cidrs.iter().map(|c| c.as_str().to_string()).collect();
    let wg_peer_snippet = req.wg_pubkey.as_deref().map(|pubk| {
        format!(
            "[Peer]\n# agent_id = {}\nPublicKey = {}\nAllowedIPs = {}\n",
            req.agent_id,
            pubk.trim(),
            wg_allowed_ips.join(", ")
        )
    });

    let bundle = PairingBundle {
        version: PAIRING_BUNDLE_VERSION,
        agent_id: req.agent_id.clone(),
        gateway_addr: gateway_addr.to_string(),
        cert_sha256: cert_sha256.clone(),
        peer_proof_key: peer_proof_key.clone(),
        cap_token: cap_token.clone(),
        issued_at_ms: req.now_ms,
        wg_peer_pubkey: req.wg_pubkey.as_deref().map(|s| s.trim().to_string()),
        wg_allowed_ips: Some(wg_allowed_ips),
    };
    bundle.validate().map_err(EnrollError::Validation)?;

    let mut bundle_json = serde_json::to_string_pretty(&bundle)?;
    bundle_json.push('\n');

    upsert_secrets_env_0600(&req.secrets_file_path, &peer_key_env, &peer_proof_key)?;
    gw_cfg.write_file_atomic(&req.peers_config_path)?;
    write_file_0600_atomic(&req.bundle_out_path, bundle_json.as_bytes())?;

    Ok(PeerEnrollResult {
        agent_id: req.agent_id.clone(),
        cert_sha256,
        peer_key_env,
        peers_config_path: req.peers_config_path.clone(),
        secrets_file_path: req.secrets_file_path.clone(),
        bundle_out_path: req.bundle_out_path.clone(),
        replaced,
        max_risk_tier: req.max_risk_tier.as_short_str().to_string(),
        token_id: cap_token.token_id,
        token_expires_at_ms,
        wg_peer_snippet,
    })
}

/// Mints and signs a fresh short-lived [`CapabilityToken`] for an already
/// enrolled, enabled peer while enforcing the peer's `max_risk_tier` ceiling.
pub fn mint_token(req: &TokenMintRequest) -> Result<TokenMintResult, EnrollError> {
    if !is_valid_agent_id(&req.agent_id) {
        return Err(EnrollError::Validation(format!(
            "invalid agent_id '{}'",
            req.agent_id
        )));
    }
    validate_token_scope(
        &req.path_patterns,
        &req.allowed_ops,
        req.ttl_ms,
        req.rate_limit_per_min,
    )?;

    let cfg = GatewayConfig::from_file(&req.peers_config_path)?;
    let peer = cfg.find_by_agent(&req.agent_id).ok_or_else(|| {
        EnrollError::Validation(format!(
            "peer '{}' is not enrolled in '{}'",
            req.agent_id,
            req.peers_config_path.display()
        ))
    })?;
    if !peer.enabled {
        return Err(EnrollError::Validation(format!(
            "peer '{}' is disabled in '{}'; refusing token mint",
            req.agent_id,
            req.peers_config_path.display()
        )));
    }
    if req.requested_tier > peer.max_risk_tier {
        return Err(EnrollError::Validation(format!(
            "requested tier {} exceeds peer '{}' ceiling {} in gateway policy",
            req.requested_tier.as_short_str(),
            req.agent_id,
            peer.max_risk_tier.as_short_str()
        )));
    }

    let token_secret =
        read_secret_from_env_or_file(&req.token_secret_env, req.secrets_file_path.as_deref())?;
    let token_nonce = random_hex_bytes(6)?;
    let expires_at_ms = req.now_ms.saturating_add(req.ttl_ms);

    let mut token = CapabilityToken {
        token_id: format!("tok-{}-{token_nonce}", req.agent_id),
        subject_agent_id: req.agent_id.clone(),
        path_patterns: req.path_patterns.clone(),
        allowed_ops: req.allowed_ops.clone(),
        max_risk_tier: req.requested_tier,
        delegation_depth: 0,
        max_delegation_depth: 1,
        expires_at_ms,
        rate_limit_per_min: req.rate_limit_per_min,
        token_budget: req.token_budget,
        hmac_sha256: String::new(),
    };
    sign_token(&mut token, &token_secret);

    let mut json = serde_json::to_string_pretty(&token)?;
    json.push('\n');
    write_file_0600_atomic(&req.out_path, json.as_bytes())?;

    Ok(TokenMintResult {
        agent_id: req.agent_id.clone(),
        token_id: token.token_id,
        max_risk_tier: req.requested_tier.as_short_str().to_string(),
        expires_at_ms,
        out_path: req.out_path.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::verify_token_signature;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hal_p5c_enroll_{}_{}_{}",
            tag,
            std::process::id(),
            random_hex_bytes(4).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn enroll_peer_and_mint_token_enforces_perms_and_tier_ceiling() {
        let dir = temp_dir("flow");
        let peers_cfg = dir.join("gateway-peers.toml");
        let secrets_env = dir.join("secrets.env");
        let bundle_out = dir.join("remote-laptop-01.pairing-bundle.json");
        let token_out = dir.join("renewed.cap.json");
        let secret_env_name = "HAL_P5C_TEST_SIGNING_SECRET";

        upsert_secrets_env_0600(&secrets_env, secret_env_name, "test-signing-secret-xyz").unwrap();

        let enroll_res = enroll_peer(&PeerEnrollRequest {
            agent_id: "remote-laptop-01".to_string(),
            allowed_ips: vec!["10.99.0.10".to_string()],
            gateway_addr: "127.0.0.1:9443".to_string(),
            peers_config_path: peers_cfg.clone(),
            secrets_file_path: secrets_env.clone(),
            bundle_out_path: bundle_out.clone(),
            token_secret_env: secret_env_name.to_string(),
            peer_key_env: None,
            cert_sha256: None,
            path_patterns: vec!["/vault/**".to_string(), "/habitat/**".to_string()],
            allowed_ops: vec!["read".to_string(), "lock".to_string()],
            max_risk_tier: RiskTier::L1ReversibleCow,
            ttl_ms: 3_600_000,
            rate_limit_per_min: 60,
            token_budget: Some(1000),
            wg_pubkey: Some("LaptopWgPubKey123=".to_string()),
            replace: false,
            now_ms: 1_700_000_000_000,
        })
        .unwrap();

        assert_eq!(enroll_res.peer_key_env, "HAL_PEER_KEY_REMOTE_LAPTOP_01");
        assert!(enroll_res
            .wg_peer_snippet
            .as_deref()
            .unwrap()
            .contains("10.99.0.10/32"));

        #[cfg(unix)]
        {
            let secrets_mode = std::fs::metadata(&secrets_env).unwrap().permissions().mode() & 0o777;
            let bundle_mode = std::fs::metadata(&bundle_out).unwrap().permissions().mode() & 0o777;
            assert_eq!(secrets_mode, 0o600);
            assert_eq!(bundle_mode, 0o600);
        }

        let loaded_cfg = GatewayConfig::from_file(&peers_cfg).unwrap();
        assert_eq!(loaded_cfg.peers.len(), 1);
        assert_eq!(
            loaded_cfg.peers[0].allowed_cidrs[0].as_str(),
            "10.99.0.10/32"
        );

        let bundle: PairingBundle =
            serde_json::from_str(&std::fs::read_to_string(&bundle_out).unwrap()).unwrap();
        bundle.validate().unwrap();
        assert!(verify_token_signature(
            &bundle.cap_token,
            b"test-signing-secret-xyz"
        ));
        let stored_key = read_secret_from_env_or_file(
            "HAL_PEER_KEY_REMOTE_LAPTOP_01",
            Some(&secrets_env),
        )
        .unwrap();
        assert_eq!(stored_key, bundle.peer_proof_key.as_bytes());

        // Mint within tier ceiling succeeds
        let mint_ok = mint_token(&TokenMintRequest {
            agent_id: "remote-laptop-01".to_string(),
            peers_config_path: peers_cfg.clone(),
            secrets_file_path: Some(secrets_env.clone()),
            token_secret_env: secret_env_name.to_string(),
            out_path: token_out.clone(),
            path_patterns: vec!["/vault/**".to_string()],
            allowed_ops: vec!["read".to_string()],
            requested_tier: RiskTier::L1ReversibleCow,
            ttl_ms: 1_800_000,
            rate_limit_per_min: 30,
            token_budget: Some(500),
            now_ms: 1_700_000_010_000,
        })
        .unwrap();
        assert_eq!(mint_ok.max_risk_tier, "L1");

        // Mint above tier ceiling (L2 > L1) fails
        let exceed = mint_token(&TokenMintRequest {
            agent_id: "remote-laptop-01".to_string(),
            peers_config_path: peers_cfg.clone(),
            secrets_file_path: Some(secrets_env.clone()),
            token_secret_env: secret_env_name.to_string(),
            out_path: token_out.clone(),
            path_patterns: vec!["/vault/**".to_string()],
            allowed_ops: vec!["write".to_string()],
            requested_tier: RiskTier::L2IrreversibleOrExternal,
            ttl_ms: 1_800_000,
            rate_limit_per_min: 30,
            token_budget: None,
            now_ms: 1_700_000_020_000,
        });
        assert!(matches!(exceed, Err(EnrollError::Validation(_))));

        // Mint for disabled peer fails
        let mut disabled_cfg = loaded_cfg;
        disabled_cfg.peers[0].enabled = false;
        disabled_cfg.write_file_atomic(&peers_cfg).unwrap();
        let disabled_mint = mint_token(&TokenMintRequest {
            agent_id: "remote-laptop-01".to_string(),
            peers_config_path: peers_cfg,
            secrets_file_path: Some(secrets_env),
            token_secret_env: secret_env_name.to_string(),
            out_path: token_out,
            path_patterns: vec!["/vault/**".to_string()],
            allowed_ops: vec!["read".to_string()],
            requested_tier: RiskTier::L0ReadOnly,
            ttl_ms: 60_000,
            rate_limit_per_min: 10,
            token_budget: None,
            now_ms: 1_700_000_030_000,
        });
        assert!(matches!(disabled_mint, Err(EnrollError::Validation(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
