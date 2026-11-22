use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Agent access & authentication mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentAuthKind {
    LocalNoIpJail,
    EphemeralWorker,
    RemoteGatewayMtls,
}

/// Trust domain assigned to an agent principal (used by IPC Matrix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustDomain {
    ResidentCore,
    WorkspaceWorker,
    UntrustedResearch,
    RemoteExternal,
}

impl FromStr for TrustDomain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "resident_core" | "ResidentCore" => Ok(Self::ResidentCore),
            "workspace_worker" | "WorkspaceWorker" => Ok(Self::WorkspaceWorker),
            "untrusted_research" | "UntrustedResearch" => Ok(Self::UntrustedResearch),
            "remote_external" | "RemoteExternal" => Ok(Self::RemoteExternal),
            other => Err(format!("unknown trust domain '{other}'")),
        }
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ResidentCore => "resident_core",
            Self::WorkspaceWorker => "workspace_worker",
            Self::UntrustedResearch => "untrusted_research",
            Self::RemoteExternal => "remote_external",
        };
        f.write_str(s)
    }
}

/// Strongly typed agent identity verified by kernel LOCAL_PEERCRED or gateway mTLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: String,
    pub trust_domain: TrustDomain,
    pub auth_kind: AgentAuthKind,
    pub parent_agent_id: Option<String>,
    pub peer_cred_or_cert_fp: String,
}

/// Data provenance trust classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    TrustedSystem,
    HumanOob,
    PrivateLocal,
    UntrustedExternal,
}

/// Information-flow taint labels preventing lethal trifecta exfiltration and taint laundering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaintTag {
    UntrustedWeb,
    UntrustedMsg,
    UntrustedCode,
    PrivateVault,
    SecretDerived,
}

impl TaintTag {
    #[must_use]
    pub fn is_untrusted(self) -> bool {
        matches!(
            self,
            Self::UntrustedWeb | Self::UntrustedMsg | Self::UntrustedCode
        )
    }

    #[must_use]
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::PrivateVault | Self::SecretDerived)
    }
}

/// Uniform capability risk tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTier {
    L0ReadOnly,
    L1ReversibleCow,
    L2IrreversibleOrExternal,
}

impl RiskTier {
    #[must_use]
    pub fn from_short_str(s: &str) -> Option<Self> {
        match s.trim() {
            "L0" | "L0ReadOnly" => Some(Self::L0ReadOnly),
            "L1" | "L1ReversibleCow" => Some(Self::L1ReversibleCow),
            "L2" | "L2IrreversibleOrExternal" => Some(Self::L2IrreversibleOrExternal),
            _ => None,
        }
    }
}

/// Four-level global system degradation state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemMode {
    Autonomous,
    Advisory,
    Frozen,
    Lockdown,
}

impl SystemMode {
    /// Monotonic severity ordinal (`0` = least restricted, `3` = most restricted).
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Autonomous => 0,
            Self::Advisory => 1,
            Self::Frozen => 2,
            Self::Lockdown => 3,
        }
    }
}

/// Plan 9-style Habitat node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    Sensor,
    Effector,
    Dual,
}

/// Static capability metadata registered on hal-bus for a Habitat namespace node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub path: String,
    pub kind: NodeKind,
    pub risk_tier: RiskTier,
    pub default_taint: Option<TaintTag>,
    pub reversible: bool,
    pub description: String,
}

/// Unified perception event envelope pushed from Layer 2 adapters through hal-bus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: String,
    pub ts_ms: u64,
    pub source_path: String,
    pub producer_actor: String,
    pub trust_level: TrustLevel,
    pub taint_tags: BTreeSet<TaintTag>,
    pub payload: serde_json::Value,
}

/// Signed capability token issued by hal-policy / hal-oob with monotonic attenuation support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: String,
    pub subject_agent_id: String,
    pub path_patterns: Vec<String>,
    pub allowed_ops: Vec<String>,
    pub max_risk_tier: RiskTier,
    pub delegation_depth: u8,
    pub max_delegation_depth: u8,
    pub expires_at_ms: u64,
    pub rate_limit_per_min: u32,
    pub token_budget: Option<u64>,
    pub hmac_sha256: String,
}

/// Controlled inter-agent IPC message carrying transitive taint propagation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpcMessage {
    pub msg_id: String,
    pub from_agent: String,
    pub to_agent: String,
    pub ts_ms: u64,
    pub propagated_taints: BTreeSet<TaintTag>,
    pub schema_id: String,
    pub payload: serde_json::Value,
}

/// Short-lived exclusive lease for shared workspaces or physical effectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLease {
    pub lease_id: String,
    pub resource_path: String,
    pub holder_agent_id: String,
    pub priority: u8,
    pub acquired_at_ms: u64,
    pub expires_at_ms: u64,
    pub preemptible_by_oob: bool,
}

/// Typed action proposal submitted by cognitive agents to hal-bus -> hal-policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionProposal {
    pub proposal_id: String,
    pub episode_id: String,
    pub agent_id: String,
    pub cap_token: CapabilityToken,
    pub target_path: String,
    pub action: String,
    pub args: serde_json::Value,
    pub reason: String,
    pub trigger_event_ids: Vec<String>,
}

/// Deterministic decision returned by hal-policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum PolicyDecision {
    Allow {
        pre_snapshot_id: Option<String>,
        applied_taints: BTreeSet<TaintTag>,
    },
    Deny {
        code: String,
        reason: String,
    },
    RequireApproval {
        approval_id: String,
        risk_tier: RiskTier,
        summary: String,
        diff_preview: Option<String>,
    },
    AutoFreeze {
        target_agent_id: Option<String>,
        trigger_rule: String,
        reason: String,
    },
}

/// Hash-chained black-box audit record managed by hal-audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts_ms: u64,
    pub principal: AgentPrincipal,
    pub episode_id: String,
    pub target_path: String,
    pub action: String,
    pub trigger_event_ids: Vec<String>,
    pub proposal_id: Option<String>,
    pub decision_summary: String,
    pub workspace_snapshot_id: Option<String>,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Metadata tracking an atomic ZFS disk + AI memory dual snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualSnapshot {
    pub snapshot_tag: String,
    pub agent_id: String,
    pub episode_id: String,
    pub workspace_dataset: String,
    pub memory_dataset: String,
    pub created_at_ms: u64,
    pub reason: String,
}
