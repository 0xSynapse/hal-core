use crate::invariants::check_hard_invariants;
use crate::taint::TaintTracker;
use hal_proto::{
    delegate_token, path_matches_pattern, verify_token_signature, ActionProposal, AgentPrincipal,
    AttenuationError, CapabilityToken, DelegationSpec, PolicyDecision, RiskTier, SystemMode,
    TaintTag,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

/// Policy engine runtime configuration.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    pub token_secret: Vec<u8>,
}

/// Administrative / delegation errors from `PolicyEngine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Unauthorized(String),
    UnidirectionalLockViolation { current: SystemMode, requested: SystemMode },
    Attenuation(AttenuationError),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "unauthorized policy operation: {msg}"),
            Self::UnidirectionalLockViolation { current, requested } => write!(
                f,
                "unidirectional mode lock forbids non-OOB transition {current:?} -> {requested:?}"
            ),
            Self::Attenuation(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<AttenuationError> for PolicyError {
    fn from(value: AttenuationError) -> Self {
        Self::Attenuation(value)
    }
}

/// Deterministic brainstem policy engine enforcing risk tiers, hard invariants,
/// taint propagation, surgical/global circuit breaking, and capability attenuation.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    system_mode: SystemMode,
    frozen_agents: BTreeMap<String, String>,
    taints: TaintTracker,
    rate_windows: HashMap<String, VecDeque<u64>>,
    budget_used: HashMap<String, u64>,
    seq_counter: u64,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            system_mode: SystemMode::Autonomous,
            frozen_agents: BTreeMap::new(),
            taints: TaintTracker::default(),
            rate_windows: HashMap::new(),
            budget_used: HashMap::new(),
            seq_counter: 0,
        }
    }

    #[must_use]
    pub fn system_mode(&self) -> SystemMode {
        self.system_mode
    }

    #[must_use]
    pub fn is_agent_frozen(&self, agent_id: &str) -> Option<&str> {
        self.frozen_agents.get(agent_id).map(String::as_str)
    }

    /// Freezes a single agent without disrupting healthy agents (`halctl agent freeze` / watchdog).
    pub fn freeze_agent(
        &mut self,
        agent_id: &str,
        reason: String,
        caller_is_oob: bool,
        caller_is_watchdog: bool,
    ) -> Result<(), PolicyError> {
        if !caller_is_oob && !caller_is_watchdog {
            return Err(PolicyError::Unauthorized(
                "only hal-oob or hal-watchdog may freeze an agent".to_string(),
            ));
        }
        self.frozen_agents.insert(agent_id.to_string(), reason);
        Ok(())
    }

    /// Unfreezes a single agent (strictly OOB only).
    pub fn unfreeze_agent(
        &mut self,
        agent_id: &str,
        caller_is_oob: bool,
    ) -> Result<bool, PolicyError> {
        if !caller_is_oob {
            return Err(PolicyError::Unauthorized(
                "only human OOB control plane may unfreeze an agent".to_string(),
            ));
        }
        Ok(self.frozen_agents.remove(agent_id).is_some())
    }

    /// Updates global degradation mode. Non-OOB callers (watchdog) may only tighten severity.
    pub fn set_mode(
        &mut self,
        requested: SystemMode,
        caller_is_oob: bool,
        caller_is_watchdog: bool,
    ) -> Result<SystemMode, PolicyError> {
        if !caller_is_oob && !caller_is_watchdog {
            return Err(PolicyError::Unauthorized(
                "only hal-oob or hal-watchdog may change system mode".to_string(),
            ));
        }
        if !caller_is_oob && requested.severity() <= self.system_mode.severity() {
            return Err(PolicyError::UnidirectionalLockViolation {
                current: self.system_mode,
                requested,
            });
        }
        self.system_mode = requested;
        Ok(self.system_mode)
    }

    pub fn record_event_taints(
        &mut self,
        agent_id: &str,
        episode_id: &str,
        tags: impl IntoIterator<Item = TaintTag>,
    ) -> BTreeSet<TaintTag> {
        self.taints.record_taints(agent_id, episode_id, tags)
    }

    pub fn propagate_ipc_taints(
        &mut self,
        from_agent: &str,
        from_ep: &str,
        to_agent: &str,
        to_ep: &str,
        msg_tags: &BTreeSet<TaintTag>,
    ) -> BTreeSet<TaintTag> {
        self.taints
            .propagate_ipc(from_agent, from_ep, to_agent, to_ep, msg_tags)
    }

    #[must_use]
    pub fn episode_taints(&self, agent_id: &str, episode_id: &str) -> BTreeSet<TaintTag> {
        self.taints.get_taints(agent_id, episode_id)
    }

    pub fn delegate_token(
        &self,
        parent: &CapabilityToken,
        spec: DelegationSpec,
        now_ms: u64,
    ) -> Result<CapabilityToken, PolicyError> {
        Ok(delegate_token(parent, spec, &self.config.token_secret, now_ms)?)
    }

    fn deny(code: &str, reason: impl Into<String>) -> PolicyDecision {
        PolicyDecision::Deny {
            code: code.to_string(),
            reason: reason.into(),
        }
    }

    /// Evaluates an `ActionProposal` against a kernel-verified `AgentPrincipal`.
    pub fn evaluate_proposal(
        &mut self,
        verified_principal: &AgentPrincipal,
        proposal: &ActionProposal,
        now_ms: u64,
        caller_is_oob: bool,
    ) -> PolicyDecision {
        if proposal.agent_id != verified_principal.agent_id
            || proposal.cap_token.subject_agent_id != verified_principal.agent_id
        {
            return Self::deny(
                "IDENTITY_MISMATCH",
                format!(
                    "verified principal '{}' does not match proposal ('{}') or token subject ('{}')",
                    verified_principal.agent_id,
                    proposal.agent_id,
                    proposal.cap_token.subject_agent_id
                ),
            );
        }

        if !caller_is_oob {
            if let Some(reason) = self.frozen_agents.get(&verified_principal.agent_id) {
                return Self::deny(
                    "AGENT_FROZEN",
                    format!("agent '{}' is frozen: {reason}", verified_principal.agent_id),
                );
            }
        }

        if !caller_is_oob && matches!(self.system_mode, SystemMode::Frozen | SystemMode::Lockdown) {
            return Self::deny(
                "SYSTEM_DEGRADED",
                format!(
                    "system mode {:?} blocks all cognitive proposals",
                    self.system_mode
                ),
            );
        }

        let tok = &proposal.cap_token;
        if !verify_token_signature(tok, &self.config.token_secret) {
            return Self::deny("INVALID_CAP_TOKEN", "capability token HMAC verification failed");
        }
        if tok.expires_at_ms <= now_ms {
            return Self::deny("TOKEN_EXPIRED", "capability token has expired");
        }
        if tok.delegation_depth > tok.max_delegation_depth {
            return Self::deny(
                "DELEGATION_DEPTH_EXCEEDED",
                "token delegation depth exceeds max_delegation_depth",
            );
        }
        if !tok
            .path_patterns
            .iter()
            .any(|pat| path_matches_pattern(&proposal.target_path, pat))
        {
            return Self::deny(
                "CAP_SCOPE_DENIED",
                format!(
                    "target_path '{}' outside token path_patterns",
                    proposal.target_path
                ),
            );
        }
        if !tok.allowed_ops.iter().any(|op| op == &proposal.action) {
            return Self::deny(
                "CAP_OP_DENIED",
                format!("action '{}' not permitted by token", proposal.action),
            );
        }

        let cutoff = now_ms.saturating_sub(60_000);
        let rate_len = {
            let win = self
                .rate_windows
                .entry(tok.token_id.clone())
                .or_default();
            while let Some(&ts) = win.front() {
                if ts <= cutoff {
                    win.pop_front();
                } else {
                    break;
                }
            }
            win.len()
        };
        if tok.rate_limit_per_min == 0 || rate_len >= tok.rate_limit_per_min as usize {
            return Self::deny(
                "RATE_LIMIT_EXCEEDED",
                format!(
                    "token '{}' exceeded rate limit ({}/min)",
                    tok.token_id, tok.rate_limit_per_min
                ),
            );
        }

        let cost = proposal
            .args
            .get("token_cost")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        if let Some(budget) = tok.token_budget {
            let used = self
                .budget_used
                .get(&tok.token_id)
                .copied()
                .unwrap_or(0);
            if used.saturating_add(cost) > budget {
                return Self::deny(
                    "BUDGET_EXCEEDED",
                    format!("token '{}' budget exhausted ({used}/{budget})", tok.token_id),
                );
            }
        }

        if let Some((code, reason)) = check_hard_invariants(verified_principal, proposal, caller_is_oob)
        {
            return Self::deny(&code, reason);
        }

        let (tier, read_taints, is_external_egress) =
            match classify_target(&proposal.target_path, &proposal.action, &proposal.args) {
                Ok(classified) => classified,
                Err((code, reason)) => return Self::deny(code, reason),
            };

        let merged_taints = if read_taints.is_empty() {
            self.taints
                .get_taints(&verified_principal.agent_id, &proposal.episode_id)
        } else {
            self.taints.record_taints(
                &verified_principal.agent_id,
                &proposal.episode_id,
                read_taints.iter().copied(),
            )
        };

        if is_external_egress && TaintTracker::is_lethal_trifecta(&merged_taints) {
            return Self::deny(
                "TAINT_EXFIL_BLOCKED",
                format!(
                    "lethal trifecta taint conflict blocked external egress on '{}': {:?}",
                    proposal.target_path, merged_taints
                ),
            );
        }

        if !caller_is_oob
            && self.system_mode == SystemMode::Advisory
            && tier > RiskTier::L0ReadOnly
        {
            return Self::deny(
                "ADVISORY_READ_ONLY",
                format!(
                    "system mode Advisory blocks {:?} action on '{}'",
                    tier, proposal.target_path
                ),
            );
        }

        if tier > tok.max_risk_tier {
            return Self::deny(
                "RISK_TIER_DENIED",
                format!(
                    "action requires {:?} but token max_risk_tier is {:?}",
                    tier, tok.max_risk_tier
                ),
            );
        }

        self.rate_windows
            .entry(tok.token_id.clone())
            .or_default()
            .push_back(now_ms);
        if tok.token_budget.is_some() {
            let entry = self.budget_used.entry(tok.token_id.clone()).or_insert(0);
            *entry = entry.saturating_add(cost);
        }

        self.seq_counter += 1;
        match tier {
            RiskTier::L0ReadOnly => PolicyDecision::Allow {
                pre_snapshot_id: None,
                applied_taints: merged_taints,
            },
            RiskTier::L1ReversibleCow => PolicyDecision::Allow {
                pre_snapshot_id: Some(format!(
                    "{}_{}_{}",
                    verified_principal.agent_id, proposal.episode_id, self.seq_counter
                )),
                applied_taints: merged_taints,
            },
            RiskTier::L2IrreversibleOrExternal => PolicyDecision::RequireApproval {
                approval_id: format!("appr_{}", self.seq_counter),
                risk_tier: RiskTier::L2IrreversibleOrExternal,
                summary: format!(
                    "{} proposed '{}' on '{}' (reason: {})",
                    verified_principal.agent_id,
                    proposal.action,
                    proposal.target_path,
                    proposal.reason
                ),
                diff_preview: None,
            },
        }
    }
}

fn is_read_action(action: &str) -> bool {
    matches!(
        action,
        "read" | "list" | "stat" | "query" | "inspect" | "verify" | "subscribe"
    )
}

fn matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn classify_target(
    target_path: &str,
    action: &str,
    args: &serde_json::Value,
) -> Result<(RiskTier, BTreeSet<TaintTag>, bool), (&'static str, String)> {
    let mut taints = BTreeSet::new();

    if matches_prefix(target_path, "/vault") {
        taints.insert(TaintTag::PrivateVault);
        let tier = if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L2IrreversibleOrExternal
        };
        return Ok((tier, taints, false));
    }

    if matches_prefix(target_path, "/net/broker") {
        if matches!(action, "health" | "status") {
            return Ok((RiskTier::L0ReadOnly, taints, false));
        }
        return Ok((RiskTier::L2IrreversibleOrExternal, taints, true));
    }

    if matches_prefix(target_path, "/net/flows")
        || matches_prefix(target_path, "/net/dns")
        || matches_prefix(target_path, "/net/policy")
    {
        let tier = if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L2IrreversibleOrExternal
        };
        return Ok((tier, taints, false));
    }

    if matches_prefix(target_path, "/work") {
        if args
            .get("untrusted_source")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            taints.insert(TaintTag::UntrustedCode);
        }
        let tier = if target_path.ends_with("/merge") {
            RiskTier::L2IrreversibleOrExternal
        } else if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L1ReversibleCow
        };
        return Ok((tier, taints, false));
    }

    if matches_prefix(target_path, "/habitat/entry") || matches_prefix(target_path, "/habitat/power")
    {
        let tier = if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L2IrreversibleOrExternal
        };
        return Ok((tier, taints, false));
    }

    if matches_prefix(target_path, "/habitat") {
        let tier = if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L1ReversibleCow
        };
        return Ok((tier, taints, false));
    }

    if matches_prefix(target_path, "/sys") || matches_prefix(target_path, "/agents") {
        let tier = if is_read_action(action) {
            RiskTier::L0ReadOnly
        } else {
            RiskTier::L2IrreversibleOrExternal
        };
        return Ok((tier, taints, false));
    }

    Err((
        "UNKNOWN_NAMESPACE_PATH",
        format!("unrecognized Habitat namespace path '{target_path}'"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::{sign_token, AgentAuthKind, TrustDomain};

    const SECRET: &[u8] = b"hal-policy-unit-test-secret-key!";

    fn make_principal(agent_id: &str, trust_domain: TrustDomain) -> AgentPrincipal {
        AgentPrincipal {
            agent_id: agent_id.to_string(),
            trust_domain,
            auth_kind: AgentAuthKind::LocalNoIpJail,
            parent_agent_id: None,
            peer_cred_or_cert_fp: "uid:1001".to_string(),
        }
    }

    fn make_token(
        agent_id: &str,
        paths: &[&str],
        ops: &[&str],
        tier: RiskTier,
        rate: u32,
        budget: Option<u64>,
    ) -> CapabilityToken {
        let mut t = CapabilityToken {
            token_id: format!("tok_{agent_id}"),
            subject_agent_id: agent_id.to_string(),
            path_patterns: paths.iter().map(|s| (*s).to_string()).collect(),
            allowed_ops: ops.iter().map(|s| (*s).to_string()).collect(),
            max_risk_tier: tier,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: 9_000_000,
            rate_limit_per_min: rate,
            token_budget: budget,
            hmac_sha256: String::new(),
        };
        sign_token(&mut t, SECRET);
        t
    }

    fn make_proposal(
        agent_id: &str,
        episode_id: &str,
        tok: CapabilityToken,
        path: &str,
        action: &str,
    ) -> ActionProposal {
        ActionProposal {
            proposal_id: "prop_1".to_string(),
            episode_id: episode_id.to_string(),
            agent_id: agent_id.to_string(),
            cap_token: tok,
            target_path: path.to_string(),
            action: action.to_string(),
            args: serde_json::json!({}),
            reason: "unit test".to_string(),
            trigger_event_ids: vec!["evt_1".to_string()],
        }
    }

    #[test]
    fn lethal_trifecta_blocks_external_egress_even_with_l2_token() {
        let mut engine = PolicyEngine::new(PolicyConfig {
            token_secret: SECRET.to_vec(),
        });
        let p = make_principal("agent-coder", TrustDomain::WorkspaceWorker);
        let tok = make_token(
            "agent-coder",
            &["/vault/**", "/net/broker/**"],
            &["read", "http_post"],
            RiskTier::L2IrreversibleOrExternal,
            30,
            Some(100),
        );

        let r1 = engine.evaluate_proposal(
            &p,
            &make_proposal("agent-coder", "ep1", tok.clone(), "/vault/docs/secret_plan.txt", "read"),
            1000,
            false,
        );
        assert!(matches!(
            r1,
            PolicyDecision::Allow { ref applied_taints, .. } if applied_taints.contains(&TaintTag::PrivateVault)
        ));

        engine.record_event_taints("agent-coder", "ep1", [TaintTag::UntrustedWeb]);

        let r2 = engine.evaluate_proposal(
            &p,
            &make_proposal("agent-coder", "ep1", tok, "/net/broker/http", "http_post"),
            1001,
            false,
        );
        assert!(matches!(
            r2,
            PolicyDecision::Deny { ref code, .. } if code == "TAINT_EXFIL_BLOCKED"
        ));
    }

    #[test]
    fn hard_invariants_and_unidirectional_mode_lock_enforced() {
        let mut engine = PolicyEngine::new(PolicyConfig {
            token_secret: SECRET.to_vec(),
        });
        let p = make_principal("agent-coder", TrustDomain::WorkspaceWorker);
        let tok = make_token(
            "agent-coder",
            &["/**"],
            &["write", "read", "stop"],
            RiskTier::L2IrreversibleOrExternal,
            30,
            None,
        );

        let d1 = engine.evaluate_proposal(
            &p,
            &make_proposal("agent-coder", "ep1", tok.clone(), "/etc/pf.conf", "write"),
            1000,
            false,
        );
        assert!(matches!(
            d1,
            PolicyDecision::Deny { ref code, .. } if code == "HARD_INVARIANT_IMMUTABLE_TCB"
        ));

        let d2 = engine.evaluate_proposal(
            &p,
            &make_proposal("agent-coder", "ep1", tok, "/pool/audit/hal-audit.log", "stop"),
            1001,
            false,
        );
        assert!(matches!(
            d2,
            PolicyDecision::Deny { ref code, .. } if code == "HARD_INVARIANT_PROTECTED_SUBSYSTEM"
        ));

        assert_eq!(
            engine.set_mode(SystemMode::Advisory, false, true).unwrap(),
            SystemMode::Advisory
        );
        assert_eq!(
            engine.set_mode(SystemMode::Frozen, false, true).unwrap(),
            SystemMode::Frozen
        );
        let err = engine.set_mode(SystemMode::Autonomous, false, true).unwrap_err();
        assert!(matches!(err, PolicyError::UnidirectionalLockViolation { .. }));

        assert_eq!(
            engine.set_mode(SystemMode::Autonomous, true, false).unwrap(),
            SystemMode::Autonomous
        );
    }

    #[test]
    fn rate_limit_and_budget_enforcement() {
        let mut engine = PolicyEngine::new(PolicyConfig {
            token_secret: SECRET.to_vec(),
        });
        let p = make_principal("agent-coder", TrustDomain::WorkspaceWorker);
        let tok = make_token(
            "agent-coder",
            &["/work/**"],
            &["write"],
            RiskTier::L1ReversibleCow,
            2,
            Some(2),
        );
        let prop = make_proposal("agent-coder", "ep1", tok, "/work/agents/coder/episodes/ep1/fs", "write");

        assert!(matches!(
            engine.evaluate_proposal(&p, &prop, 1_000, false),
            PolicyDecision::Allow { pre_snapshot_id: Some(_), .. }
        ));
        assert!(matches!(
            engine.evaluate_proposal(&p, &prop, 2_000, false),
            PolicyDecision::Allow { pre_snapshot_id: Some(_), .. }
        ));
        let denied = engine.evaluate_proposal(&p, &prop, 3_000, false);
        assert!(matches!(
            denied,
            PolicyDecision::Deny { ref code, .. } if code == "RATE_LIMIT_EXCEEDED"
        ));

        let budget_denied = engine.evaluate_proposal(&p, &prop, 65_000, false);
        assert!(matches!(
            budget_denied,
            PolicyDecision::Deny { ref code, .. } if code == "BUDGET_EXCEEDED"
        ));
    }
}
