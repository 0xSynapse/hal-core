use crate::config::WatchdogConfig;
use hal_proto::{AuditRecord, SystemMode};
use std::collections::{BTreeSet, HashMap, VecDeque};

const SECURITY_DENY_PREFIXES: &[&str] = &[
    "TAINT_EXFIL_BLOCKED",
    "IPC_MATRIX_DENIED",
    "HARD_INVARIANT_",
    "IDENTITY_MISMATCH",
    "IDENTITY_SPOOF_DENIED",
    "OOB_SPOOF_DENIED",
    "DLP_SECRET_LEAK_BLOCKED",
    "ATTENUATION_DENIED",
];

/// Corrective circuit-breaker action emitted by `WatchdogEngine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchdogAction {
    FreezeAgent {
        agent_id: String,
        rule: &'static str,
        reason: String,
    },
    DegradeSystemMode {
        mode: SystemMode,
        rule: &'static str,
        reason: String,
    },
}

/// Deterministic sliding-window anomaly detector and unidirectional breaker.
#[derive(Debug, Clone)]
pub struct WatchdogEngine {
    config: WatchdogConfig,
    denial_windows: HashMap<String, VecDeque<u64>>,
    lease_windows: HashMap<String, VecDeque<u64>>,
    pf_drop_windows: HashMap<String, VecDeque<u64>>,
    sensor_divergence_streaks: HashMap<String, u32>,
    auto_frozen_agents: BTreeSet<String>,
    highest_degraded_mode: SystemMode,
}

impl WatchdogEngine {
    #[must_use]
    pub fn new(config: WatchdogConfig) -> Self {
        Self {
            config,
            denial_windows: HashMap::new(),
            lease_windows: HashMap::new(),
            pf_drop_windows: HashMap::new(),
            sensor_divergence_streaks: HashMap::new(),
            auto_frozen_agents: BTreeSet::new(),
            highest_degraded_mode: SystemMode::Autonomous,
        }
    }

    #[must_use]
    pub fn config(&self) -> &WatchdogConfig {
        &self.config
    }

    #[must_use]
    pub fn auto_frozen_agents(&self) -> &BTreeSet<String> {
        &self.auto_frozen_agents
    }

    #[must_use]
    pub fn highest_degraded_mode(&self) -> SystemMode {
        self.highest_degraded_mode
    }

    fn maybe_escalate_mode(
        &mut self,
        mode: SystemMode,
        rule: &'static str,
        reason: String,
        out: &mut Vec<WatchdogAction>,
    ) {
        if mode.severity() > self.highest_degraded_mode.severity() {
            self.highest_degraded_mode = mode;
            out.push(WatchdogAction::DegradeSystemMode { mode, rule, reason });
        }
    }

    fn push_window(
        map: &mut HashMap<String, VecDeque<u64>>,
        key: &str,
        ts_ms: u64,
        window_ms: u64,
    ) -> usize {
        let cutoff = ts_ms.saturating_sub(window_ms);
        let q = map.entry(key.to_string()).or_default();
        q.push_back(ts_ms);
        while let Some(&front) = q.front() {
            if front < cutoff {
                q.pop_front();
            } else {
                break;
            }
        }
        q.len()
    }

    fn try_freeze_agent(
        &mut self,
        agent_id: &str,
        rule: &'static str,
        reason: String,
        out: &mut Vec<WatchdogAction>,
    ) {
        if !self.auto_frozen_agents.insert(agent_id.to_string()) {
            return;
        }
        out.push(WatchdogAction::FreezeAgent {
            agent_id: agent_id.to_string(),
            rule,
            reason,
        });

        let frozen_count = self.auto_frozen_agents.len();
        if frozen_count > self.config.global_escalate_frozen_agents {
            self.maybe_escalate_mode(
                SystemMode::Frozen,
                "MULTI_AGENT_CASCADE_ESCALATION",
                format!(
                    "{frozen_count} agents auto-frozen within session; escalating globally to FROZEN"
                ),
                out,
            );
        } else if frozen_count >= self.config.global_escalate_frozen_agents {
            self.maybe_escalate_mode(
                SystemMode::Advisory,
                "MULTI_AGENT_CASCADE_ESCALATION",
                format!(
                    "{frozen_count} agents auto-frozen within session; degrading globally to ADVISORY"
                ),
                out,
            );
        }
    }

    /// Evaluates one verified `AuditRecord` and emits surgical or global circuit-breaker actions.
    pub fn observe_audit_record(&mut self, rec: &AuditRecord) -> Vec<WatchdogAction> {
        let mut actions = Vec::new();
        let Some(code) = extract_deny_code(&rec.decision_summary) else {
            return actions;
        };

        let agent_id = &rec.principal.agent_id;
        if is_security_denial_code(code) {
            let count = Self::push_window(
                &mut self.denial_windows,
                agent_id,
                rec.ts_ms,
                self.config.denial_window_ms,
            );
            if count >= self.config.denial_burst_threshold {
                self.try_freeze_agent(
                    agent_id,
                    "DENIAL_BURST_COLLUSION_OR_EXFIL",
                    format!(
                        "agent '{agent_id}' triggered {count} security denials within {}ms (latest={code})",
                        self.config.denial_window_ms
                    ),
                    &mut actions,
                );
            }
        } else if code == "LEASE_CONFLICT" {
            let count = Self::push_window(
                &mut self.lease_windows,
                agent_id,
                rec.ts_ms,
                self.config.lease_window_ms,
            );
            if count >= self.config.lease_conflict_threshold {
                self.try_freeze_agent(
                    agent_id,
                    "LEASE_PING_PONG_CONTENTION",
                    format!(
                        "agent '{agent_id}' triggered {count} LEASE_CONFLICT events within {}ms",
                        self.config.lease_window_ms
                    ),
                    &mut actions,
                );
            }
        }

        actions
    }

    /// Evaluates a blocked direct-egress attempt logged by PF (`pflog0`).
    pub fn observe_pf_drop(
        &mut self,
        source_id: &str,
        dst: &str,
        ts_ms: u64,
    ) -> Vec<WatchdogAction> {
        let mut actions = Vec::new();
        let count = Self::push_window(
            &mut self.pf_drop_windows,
            source_id,
            ts_ms,
            self.config.pf_window_ms,
        );
        if count >= self.config.pf_drop_burst_threshold {
            self.maybe_escalate_mode(
                SystemMode::Advisory,
                "PF_DIRECT_EGRESS_BYPASS",
                format!(
                    "PF dropped {count} bypass packets from '{source_id}' toward '{dst}' within {}ms",
                    self.config.pf_window_ms
                ),
                &mut actions,
            );
        }
        actions
    }

    /// Compares deterministic Layer 0 spinal telemetry against cognitive reported readings.
    pub fn observe_sensor_check(
        &mut self,
        path: &str,
        spinal_value: f64,
        cognitive_reported: f64,
        ts_ms: u64,
    ) -> Vec<WatchdogAction> {
        let mut actions = Vec::new();
        let diff = (spinal_value - cognitive_reported).abs();
        if diff > self.config.sensor_divergence_limit_c {
            let streak = {
                let entry = self
                    .sensor_divergence_streaks
                    .entry(path.to_string())
                    .or_insert(0);
                *entry += 1;
                *entry
            };
            if streak >= 2 {
                self.maybe_escalate_mode(
                    SystemMode::Advisory,
                    "SENSOR_CONSISTENCY_DIVERGENCE",
                    format!(
                        "sensor '{path}' diverged by {diff:.2}C (> {:.2}C) for {streak} consecutive checks at {ts_ms}",
                        self.config.sensor_divergence_limit_c
                    ),
                    &mut actions,
                );
            }
        } else {
            self.sensor_divergence_streaks.insert(path.to_string(), 0);
        }
        actions
    }
}

fn extract_deny_code(summary: &str) -> Option<&str> {
    let rest = summary.strip_prefix("Deny(")?;
    let (code, _) = rest.split_once(':')?;
    Some(code.trim())
}

fn is_security_denial_code(code: &str) -> bool {
    SECURITY_DENY_PREFIXES
        .iter()
        .any(|prefix| code.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::{AgentAuthKind, AgentPrincipal, TrustDomain};

    fn test_config() -> WatchdogConfig {
        WatchdogConfig {
            version: 1,
            denial_burst_threshold: 3,
            denial_window_ms: 60_000,
            lease_conflict_threshold: 3,
            lease_window_ms: 30_000,
            pf_drop_burst_threshold: 4,
            pf_window_ms: 30_000,
            global_escalate_frozen_agents: 2,
            sensor_divergence_limit_c: 5.0,
        }
    }

    fn mk_record(seq: u64, ts_ms: u64, agent_id: &str, summary: &str) -> AuditRecord {
        AuditRecord {
            seq,
            ts_ms,
            principal: AgentPrincipal {
                agent_id: agent_id.to_string(),
                trust_domain: TrustDomain::UntrustedResearch,
                auth_kind: AgentAuthKind::LocalNoIpJail,
                parent_agent_id: None,
                peer_cred_or_cert_fp: "uid:1005".to_string(),
            },
            episode_id: "ep_w".to_string(),
            target_path: "/net/broker/http".to_string(),
            action: "http_post".to_string(),
            trigger_event_ids: Vec::new(),
            proposal_id: Some(format!("p_{seq}")),
            decision_summary: summary.to_string(),
            workspace_snapshot_id: None,
            prev_hash: "0".repeat(64),
            entry_hash: "a".repeat(64),
        }
    }

    #[test]
    fn denial_burst_lease_contention_and_cascade_trigger_monotonic_actions() {
        let mut engine = WatchdogEngine::new(test_config());

        for i in 1..=2 {
            assert!(engine
                .observe_audit_record(&mk_record(
                    i,
                    1_000 + i * 100,
                    "agent-research",
                    "Deny(TAINT_EXFIL_BLOCKED: conflict)"
                ))
                .is_empty());
        }
        let a3 = engine.observe_audit_record(&mk_record(
            3,
            1_300,
            "agent-research",
            "Deny(IPC_MATRIX_DENIED: blocked)",
        ));
        assert_eq!(
            a3,
            vec![WatchdogAction::FreezeAgent {
                agent_id: "agent-research".into(),
                rule: "DENIAL_BURST_COLLUSION_OR_EXFIL",
                reason: "agent 'agent-research' triggered 3 security denials within 60000ms (latest=IPC_MATRIX_DENIED)".into(),
            }]
        );

        // Second offending agent triggers both surgical freeze and cascade escalation to Advisory
        assert!(engine
            .observe_audit_record(&mk_record(4, 2_000, "agent-coder", "Deny(LEASE_CONFLICT: held)"))
            .is_empty());
        assert!(engine
            .observe_audit_record(&mk_record(5, 2_100, "agent-coder", "Deny(LEASE_CONFLICT: held)"))
            .is_empty());
        let cascade = engine.observe_audit_record(&mk_record(
            6,
            2_200,
            "agent-coder",
            "Deny(LEASE_CONFLICT: held)",
        ));
        assert!(matches!(
            cascade.as_slice(),
            [
                WatchdogAction::FreezeAgent { agent_id, rule: "LEASE_PING_PONG_CONTENTION", .. },
                WatchdogAction::DegradeSystemMode { mode: SystemMode::Advisory, rule: "MULTI_AGENT_CASCADE_ESCALATION", .. }
            ] if agent_id == "agent-coder"
        ));

        // 3rd agent escalates globally to Frozen
        for i in 0..3 {
            let res = engine.observe_audit_record(&mk_record(
                7 + i,
                3_000 + i * 10,
                "agent-vault",
                "Deny(HARD_INVARIANT_IMMUTABLE_TCB: forbidden)",
            ));
            if i == 2 {
                assert!(res.iter().any(|a| matches!(
                    a,
                    WatchdogAction::DegradeSystemMode {
                        mode: SystemMode::Frozen,
                        ..
                    }
                )));
            }
        }
        assert_eq!(engine.highest_degraded_mode(), SystemMode::Frozen);
    }

    #[test]
    fn pf_drops_and_sensor_divergence_degrade_only_once_toward_advisory() {
        let mut engine = WatchdogEngine::new(test_config());
        assert!(engine.observe_pf_drop("wan0", "1.1.1.1:53", 1000).is_empty());
        assert!(engine.observe_pf_drop("wan0", "1.1.1.1:53", 1100).is_empty());
        assert!(engine.observe_pf_drop("wan0", "1.1.1.1:53", 1200).is_empty());
        let acts = engine.observe_pf_drop("wan0", "1.1.1.1:53", 1300);
        assert!(matches!(
            acts.as_slice(),
            [WatchdogAction::DegradeSystemMode {
                mode: SystemMode::Advisory,
                rule: "PF_DIRECT_EGRESS_BYPASS",
                ..
            }]
        ));

        let mut s_engine = WatchdogEngine::new(test_config());
        assert!(s_engine
            .observe_sensor_check("/habitat/study/temp", 22.0, 30.0, 1000)
            .is_empty());
        let div = s_engine.observe_sensor_check("/habitat/study/temp", 22.0, 31.0, 2000);
        assert!(matches!(
            div.as_slice(),
            [WatchdogAction::DegradeSystemMode {
                mode: SystemMode::Advisory,
                rule: "SENSOR_CONSISTENCY_DIVERGENCE",
                ..
            }]
        ));
    }
}
