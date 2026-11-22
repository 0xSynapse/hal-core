use crate::canonical::{canonical_json_bytes, hex_decode, hex_encode};
use crate::types::{CapabilityToken, RiskTier};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_DOMAIN_SEP: &[u8] = b"hal-cap-token-v1:";

/// Parameters used to derive an attenuated child `CapabilityToken` from a parent token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationSpec {
    pub new_token_id: String,
    pub delegate_agent_id: String,
    pub path_patterns: Vec<String>,
    pub allowed_ops: Vec<String>,
    pub max_risk_tier: RiskTier,
    pub expires_at_ms: u64,
    pub rate_limit_per_min: u32,
    pub token_budget: Option<u64>,
}

/// Errors raised during capability token delegation or attenuation verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    InvalidParentSignature,
    InvalidChildSignature,
    ParentExpired,
    DelegationDepthExceeded,
    MaxDelegationDepthEscalated,
    RiskTierEscalated,
    ExpiryEscalated,
    RateLimitEscalated,
    EmptyOperations,
    OperationEscalated(String),
    EmptyPathPatterns,
    InvalidPathPattern(String),
    PathScopeEscalated(String),
    BudgetEscalated,
}

impl fmt::Display for AttenuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParentSignature => write!(f, "parent capability token HMAC is invalid"),
            Self::InvalidChildSignature => write!(f, "child capability token HMAC is invalid"),
            Self::ParentExpired => write!(f, "parent capability token has expired"),
            Self::DelegationDepthExceeded => write!(f, "token delegation depth limit exceeded"),
            Self::MaxDelegationDepthEscalated => {
                write!(f, "child max_delegation_depth exceeds parent")
            }
            Self::RiskTierEscalated => write!(f, "child max_risk_tier exceeds parent"),
            Self::ExpiryEscalated => write!(f, "child expiry exceeds parent expiry or is in past"),
            Self::RateLimitEscalated => write!(f, "child rate_limit_per_min exceeds parent or is 0"),
            Self::EmptyOperations => write!(f, "child token must permit at least one operation"),
            Self::OperationEscalated(op) => write!(f, "child operation '{op}' not in parent ops"),
            Self::EmptyPathPatterns => {
                write!(f, "child token must declare at least one path pattern")
            }
            Self::InvalidPathPattern(pat) => write!(f, "invalid path pattern '{pat}'"),
            Self::PathScopeEscalated(pat) => {
                write!(f, "child path pattern '{pat}' exceeds parent path scope")
            }
            Self::BudgetEscalated => write!(f, "child token_budget exceeds parent budget"),
        }
    }
}

impl std::error::Error for AttenuationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobKind<'a> {
    Recursive(Vec<&'a str>),
    Single(Vec<&'a str>),
    Exact(Vec<&'a str>),
}

fn parse_valid_path_segments(path: &str) -> Option<Vec<&str>> {
    if !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    if path == "/" {
        return Some(Vec::new());
    }
    let trimmed = path.strip_prefix('/')?;
    if trimmed.ends_with('/') {
        return None;
    }
    let mut segs = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains('*') {
            return None;
        }
        segs.push(seg);
    }
    Some(segs)
}

fn parse_glob_pattern(pattern: &str) -> Option<GlobKind<'_>> {
    if !pattern.starts_with('/') || pattern.contains('\0') {
        return None;
    }
    if pattern == "/**" {
        return Some(GlobKind::Recursive(Vec::new()));
    }
    if pattern == "/*" {
        return Some(GlobKind::Single(Vec::new()));
    }
    if pattern == "/" {
        return Some(GlobKind::Exact(Vec::new()));
    }
    let trimmed = pattern.strip_prefix('/')?;
    if trimmed.ends_with('/') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    for (idx, &seg) in parts.iter().enumerate() {
        let is_last = idx + 1 == parts.len();
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        if seg == "**" || seg == "*" {
            if !is_last {
                return None;
            }
        } else if seg.contains('*') {
            return None;
        }
    }
    match parts.last().copied() {
        Some("**") => Some(GlobKind::Recursive(parts[..parts.len() - 1].to_vec())),
        Some("*") => Some(GlobKind::Single(parts[..parts.len() - 1].to_vec())),
        _ => Some(GlobKind::Exact(parts)),
    }
}

/// Validates whether a Habitat path glob pattern is well-formed.
#[must_use]
pub fn is_valid_path_pattern(pattern: &str) -> bool {
    parse_glob_pattern(pattern).is_some()
}

/// Validates a concrete Habitat path and tests whether it matches `pattern`.
#[must_use]
pub fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let Some(path_segs) = parse_valid_path_segments(path) else {
        return false;
    };
    let Some(glob) = parse_glob_pattern(pattern) else {
        return false;
    };
    match glob {
        GlobKind::Recursive(prefix) => {
            path_segs.len() >= prefix.len() && path_segs[..prefix.len()] == prefix[..]
        }
        GlobKind::Single(prefix) => {
            path_segs.len() == prefix.len() + 1 && path_segs[..prefix.len()] == prefix[..]
        }
        GlobKind::Exact(exact) => path_segs == exact,
    }
}

/// Returns `true` iff every concrete path matched by `child` is also matched by `parent`.
#[must_use]
pub fn pattern_is_subset(child: &str, parent: &str) -> bool {
    let Some(c) = parse_glob_pattern(child) else {
        return false;
    };
    let Some(p) = parse_glob_pattern(parent) else {
        return false;
    };
    match (p, c) {
        (GlobKind::Recursive(pp), GlobKind::Recursive(cp))
        | (GlobKind::Recursive(pp), GlobKind::Single(cp))
        | (GlobKind::Recursive(pp), GlobKind::Exact(cp)) => {
            cp.len() >= pp.len() && cp[..pp.len()] == pp[..]
        }
        (GlobKind::Single(_), GlobKind::Recursive(_)) => false,
        (GlobKind::Single(pp), GlobKind::Single(cp)) => cp == pp,
        (GlobKind::Single(pp), GlobKind::Exact(cp)) => {
            cp.len() == pp.len() + 1 && cp[..pp.len()] == pp[..]
        }
        (GlobKind::Exact(pp), GlobKind::Exact(cp)) => cp == pp,
        (GlobKind::Exact(_), _) => false,
    }
}

fn token_signing_bytes(token: &CapabilityToken) -> Vec<u8> {
    let mut val = serde_json::to_value(token).expect("CapabilityToken serialization is infallible");
    if let serde_json::Value::Object(ref mut obj) = val {
        obj.remove("hmac_sha256");
    }
    let body = canonical_json_bytes(&val).expect("canonical JSON of CapabilityToken is infallible");
    let mut out = Vec::with_capacity(TOKEN_DOMAIN_SEP.len() + body.len());
    out.extend_from_slice(TOKEN_DOMAIN_SEP);
    out.extend_from_slice(&body);
    out
}

/// Signs `token` in-place using HMAC-SHA256 over its canonical fields.
pub fn sign_token(token: &mut CapabilityToken, secret: &[u8]) {
    let payload = token_signing_bytes(token);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&payload);
    token.hmac_sha256 = hex_encode(&mac.finalize().into_bytes());
}

/// Verifies `token.hmac_sha256` in constant time.
#[must_use]
pub fn verify_token_signature(token: &CapabilityToken, secret: &[u8]) -> bool {
    let Some(sig) = hex_decode(&token.hmac_sha256) else {
        return false;
    };
    if sig.len() != 32 {
        return false;
    }
    let payload = token_signing_bytes(token);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&payload);
    mac.verify_slice(&sig).is_ok()
}

fn check_attenuation_constraints(
    parent: &CapabilityToken,
    child: &CapabilityToken,
    now_ms: u64,
) -> Result<(), AttenuationError> {
    if parent.expires_at_ms <= now_ms {
        return Err(AttenuationError::ParentExpired);
    }
    let expected_depth = parent
        .delegation_depth
        .checked_add(1)
        .ok_or(AttenuationError::DelegationDepthExceeded)?;
    if child.delegation_depth != expected_depth || child.delegation_depth > parent.max_delegation_depth {
        return Err(AttenuationError::DelegationDepthExceeded);
    }
    if child.max_delegation_depth > parent.max_delegation_depth {
        return Err(AttenuationError::MaxDelegationDepthEscalated);
    }
    if child.max_risk_tier > parent.max_risk_tier {
        return Err(AttenuationError::RiskTierEscalated);
    }
    if child.expires_at_ms <= now_ms || child.expires_at_ms > parent.expires_at_ms {
        return Err(AttenuationError::ExpiryEscalated);
    }
    if child.rate_limit_per_min == 0 || child.rate_limit_per_min > parent.rate_limit_per_min {
        return Err(AttenuationError::RateLimitEscalated);
    }
    if child.allowed_ops.is_empty() {
        return Err(AttenuationError::EmptyOperations);
    }
    let parent_ops: BTreeSet<&str> = parent.allowed_ops.iter().map(String::as_str).collect();
    for op in &child.allowed_ops {
        if !parent_ops.contains(op.as_str()) {
            return Err(AttenuationError::OperationEscalated(op.clone()));
        }
    }
    if child.path_patterns.is_empty() {
        return Err(AttenuationError::EmptyPathPatterns);
    }
    for pat in &child.path_patterns {
        if parse_glob_pattern(pat).is_none() {
            return Err(AttenuationError::InvalidPathPattern(pat.clone()));
        }
        let covered = parent
            .path_patterns
            .iter()
            .any(|pp| pattern_is_subset(pat, pp));
        if !covered {
            return Err(AttenuationError::PathScopeEscalated(pat.clone()));
        }
    }
    match (parent.token_budget, child.token_budget) {
        (Some(pb), Some(cb)) if cb <= pb => {}
        (Some(_), _) => return Err(AttenuationError::BudgetEscalated),
        (None, _) => {}
    }
    Ok(())
}

/// Derives and signs an attenuated child token strictly within `parent`'s authority.
pub fn delegate_token(
    parent: &CapabilityToken,
    spec: DelegationSpec,
    secret: &[u8],
    now_ms: u64,
) -> Result<CapabilityToken, AttenuationError> {
    if !verify_token_signature(parent, secret) {
        return Err(AttenuationError::InvalidParentSignature);
    }
    let depth = parent
        .delegation_depth
        .checked_add(1)
        .ok_or(AttenuationError::DelegationDepthExceeded)?;
    let mut child = CapabilityToken {
        token_id: spec.new_token_id,
        subject_agent_id: spec.delegate_agent_id,
        path_patterns: spec.path_patterns,
        allowed_ops: spec.allowed_ops,
        max_risk_tier: spec.max_risk_tier,
        delegation_depth: depth,
        max_delegation_depth: parent.max_delegation_depth,
        expires_at_ms: spec.expires_at_ms,
        rate_limit_per_min: spec.rate_limit_per_min,
        token_budget: spec.token_budget,
        hmac_sha256: String::new(),
    };
    check_attenuation_constraints(parent, &child, now_ms)?;
    sign_token(&mut child, secret);
    Ok(child)
}

/// Validates signatures of both `parent` and `child` plus monotonic attenuation invariants.
pub fn verify_attenuation(
    parent: &CapabilityToken,
    child: &CapabilityToken,
    secret: &[u8],
    now_ms: u64,
) -> Result<(), AttenuationError> {
    if !verify_token_signature(parent, secret) {
        return Err(AttenuationError::InvalidParentSignature);
    }
    if !verify_token_signature(child, secret) {
        return Err(AttenuationError::InvalidChildSignature);
    }
    check_attenuation_constraints(parent, child, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"hal-os-test-hmac-secret-key-32b!";

    fn parent_token() -> CapabilityToken {
        let mut t = CapabilityToken {
            token_id: "tok_parent".to_string(),
            subject_agent_id: "agent-coder".to_string(),
            path_patterns: vec!["/work/agents/coder/**".to_string(), "/net/flows".to_string()],
            allowed_ops: vec!["read".to_string(), "write".to_string(), "exec".to_string()],
            max_risk_tier: RiskTier::L1ReversibleCow,
            delegation_depth: 0,
            max_delegation_depth: 2,
            expires_at_ms: 2_000_000,
            rate_limit_per_min: 60,
            token_budget: Some(1000),
            hmac_sha256: String::new(),
        };
        sign_token(&mut t, SECRET);
        t
    }

    #[test]
    fn hmac_signature_detects_tampering() {
        let tok = parent_token();
        assert!(verify_token_signature(&tok, SECRET));
        let mut tampered = tok.clone();
        tampered.max_risk_tier = RiskTier::L2IrreversibleOrExternal;
        assert!(!verify_token_signature(&tampered, SECRET));
        assert!(!verify_token_signature(&tok, b"wrong-secret"));
    }

    #[test]
    fn path_matching_and_subset_reject_traversal_and_prefix_confusion() {
        assert!(path_matches_pattern(
            "/work/agents/coder/episodes/ep1/fs",
            "/work/agents/coder/**"
        ));
        assert!(!path_matches_pattern(
            "/work/agents/coder2/episodes/ep1",
            "/work/agents/coder/**"
        ));
        assert!(!path_matches_pattern(
            "/work/agents/coder/../vault",
            "/work/agents/coder/**"
        ));
        assert!(path_matches_pattern(
            "/work/agents/coder/file",
            "/work/agents/coder/*"
        ));
        assert!(!path_matches_pattern(
            "/work/agents/coder/dir/file",
            "/work/agents/coder/*"
        ));

        assert!(pattern_is_subset(
            "/work/agents/coder/episodes/*",
            "/work/agents/coder/**"
        ));
        assert!(!pattern_is_subset(
            "/work/agents/coder/**",
            "/work/agents/coder/*"
        ));
        assert!(!pattern_is_subset("/work/agents/coder2/**", "/work/agents/coder/**"));
    }

    #[test]
    fn delegate_token_allows_strict_narrowing_and_rejects_all_escalations() {
        let p = parent_token();
        let child = delegate_token(
            &p,
            DelegationSpec {
                new_token_id: "tok_child".to_string(),
                delegate_agent_id: "agent-coder-w1".to_string(),
                path_patterns: vec!["/work/agents/coder/episodes/ep1/**".to_string()],
                allowed_ops: vec!["read".to_string(), "write".to_string()],
                max_risk_tier: RiskTier::L1ReversibleCow,
                expires_at_ms: 1_500_000,
                rate_limit_per_min: 30,
                token_budget: Some(500),
            },
            SECRET,
            1_000_000,
        )
        .expect("valid narrowing should succeed");
        assert!(verify_attenuation(&p, &child, SECRET, 1_000_000).is_ok());

        let err = delegate_token(
            &p,
            DelegationSpec {
                max_risk_tier: RiskTier::L2IrreversibleOrExternal,
                new_token_id: "t1".into(),
                delegate_agent_id: "w1".into(),
                path_patterns: vec!["/work/agents/coder/**".into()],
                allowed_ops: vec!["read".into()],
                expires_at_ms: 1_500_000,
                rate_limit_per_min: 10,
                token_budget: Some(100),
            },
            SECRET,
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(err, AttenuationError::RiskTierEscalated);

        let err = delegate_token(
            &p,
            DelegationSpec {
                max_risk_tier: RiskTier::L0ReadOnly,
                new_token_id: "t2".into(),
                delegate_agent_id: "w1".into(),
                path_patterns: vec!["/vault/**".into()],
                allowed_ops: vec!["read".into()],
                expires_at_ms: 1_500_000,
                rate_limit_per_min: 10,
                token_budget: Some(100),
            },
            SECRET,
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(err, AttenuationError::PathScopeEscalated("/vault/**".into()));

        let err = delegate_token(
            &p,
            DelegationSpec {
                max_risk_tier: RiskTier::L0ReadOnly,
                new_token_id: "t3".into(),
                delegate_agent_id: "w1".into(),
                path_patterns: vec!["/work/agents/coder/**".into()],
                allowed_ops: vec!["delete".into()],
                expires_at_ms: 1_500_000,
                rate_limit_per_min: 10,
                token_budget: Some(100),
            },
            SECRET,
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(err, AttenuationError::OperationEscalated("delete".into()));

        let err = delegate_token(
            &p,
            DelegationSpec {
                max_risk_tier: RiskTier::L0ReadOnly,
                new_token_id: "t4".into(),
                delegate_agent_id: "w1".into(),
                path_patterns: vec!["/work/agents/coder/**".into()],
                allowed_ops: vec!["read".into()],
                expires_at_ms: 1_500_000,
                rate_limit_per_min: 10,
                token_budget: None,
            },
            SECRET,
            1_000_000,
        )
        .unwrap_err();
        assert_eq!(err, AttenuationError::BudgetEscalated);
    }
}
