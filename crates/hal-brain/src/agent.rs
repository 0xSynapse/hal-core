use crate::memory::EpisodicMemoryStore;
use crate::planner::{BrokeredLlmClient, PlannedStep};
use crate::BrainError;
use hal_bus::BusClient;
use hal_gateway::{GatewayClient, GatewayRequest, GatewayResponse};
use hal_net_broker::{EgressTransport, NetBroker};
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{
    ActionProposal, AgentPrincipal, CapabilityToken, EventEnvelope, IpcMessage, PolicyDecision,
    TaintTag, TrustDomain,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Resident or dynamic cognitive agent specialization role inside Layer 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRole {
    Netsec,
    Vault,
    Coder,
    Habitat,
    Research,
    RemoteExternal,
    EphemeralWorker,
}

impl AgentRole {
    #[must_use]
    pub const fn default_agent_id(self) -> &'static str {
        match self {
            Self::Netsec => "agent-netsec",
            Self::Vault => "agent-vault",
            Self::Coder => "agent-coder",
            Self::Habitat => "agent-habitat",
            Self::Research => "agent-research",
            Self::RemoteExternal => "remote-laptop-01",
            Self::EphemeralWorker => "agent-worker",
        }
    }

    #[must_use]
    pub const fn default_trust_domain(self) -> TrustDomain {
        match self {
            Self::Netsec | Self::Vault | Self::Habitat => TrustDomain::ResidentCore,
            Self::Coder | Self::EphemeralWorker => TrustDomain::WorkspaceWorker,
            Self::Research => TrustDomain::UntrustedResearch,
            Self::RemoteExternal => TrustDomain::RemoteExternal,
        }
    }
}

impl fmt::Display for AgentRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Netsec => "netsec",
            Self::Vault => "vault",
            Self::Coder => "coder",
            Self::Habitat => "habitat",
            Self::Research => "research",
            Self::RemoteExternal => "remote_external",
            Self::EphemeralWorker => "ephemeral_worker",
        };
        f.write_str(s)
    }
}

impl FromStr for AgentRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "netsec" | "agent-netsec" => Ok(Self::Netsec),
            "vault" | "agent-vault" => Ok(Self::Vault),
            "coder" | "agent-coder" => Ok(Self::Coder),
            "habitat" | "agent-habitat" => Ok(Self::Habitat),
            "research" | "agent-research" => Ok(Self::Research),
            "remote" | "remote_external" | "remote-laptop-01" => Ok(Self::RemoteExternal),
            "worker" | "ephemeral_worker" => Ok(Self::EphemeralWorker),
            other => Err(format!("unknown hal-brain agent role '{other}'")),
        }
    }
}

/// Abstract transport allowing `CognitiveAgent` to run identically over local No-IP Jail UDS
/// or authenticated remote `hal-gateway` TCP ingress without changing cognitive logic.
pub trait CognitiveTransport {
    fn submit_proposal(
        &mut self,
        proposal: ActionProposal,
        now_ms: u64,
    ) -> Result<PolicyDecision, BrainError>;

    fn send_ipc(
        &mut self,
        message: IpcMessage,
        from_episode_id: &str,
        to_episode_id: &str,
    ) -> Result<IpcMessage, BrainError>;

    fn publish_event(
        &mut self,
        event: EventEnvelope,
        episode_id: &str,
    ) -> Result<BTreeSet<TaintTag>, BrainError>;
}

fn map_proposal_resp(resp: BusResponse) -> Result<PolicyDecision, BrainError> {
    match resp {
        BusResponse::ProposalDecision { decision } => Ok(decision),
        BusResponse::Error { code, reason } => Err(BrainError::Bus { code, reason }),
        other => Err(BrainError::Bus {
            code: "UNEXPECTED_BUS_RESPONSE".to_string(),
            reason: format!("unexpected proposal response: {other:?}"),
        }),
    }
}

fn map_ipc_resp(resp: BusResponse) -> Result<IpcMessage, BrainError> {
    match resp {
        BusResponse::IpcDelivered { message } => Ok(message),
        BusResponse::IpcDenied { code, reason } | BusResponse::Error { code, reason } => {
            Err(BrainError::Bus { code, reason })
        }
        other => Err(BrainError::Bus {
            code: "UNEXPECTED_BUS_RESPONSE".to_string(),
            reason: format!("unexpected IPC response: {other:?}"),
        }),
    }
}

fn map_event_resp(resp: BusResponse) -> Result<BTreeSet<TaintTag>, BrainError> {
    match resp {
        BusResponse::EventRecorded { episode_taints } => Ok(episode_taints),
        BusResponse::Error { code, reason } => Err(BrainError::Bus { code, reason }),
        other => Err(BrainError::Bus {
            code: "UNEXPECTED_BUS_RESPONSE".to_string(),
            reason: format!("unexpected event response: {other:?}"),
        }),
    }
}

/// UDS client adapter for resident No-IP Jail / ephemeral worker agents.
pub struct LocalBusTransport(pub BusClient);

impl CognitiveTransport for LocalBusTransport {
    fn submit_proposal(
        &mut self,
        proposal: ActionProposal,
        now_ms: u64,
    ) -> Result<PolicyDecision, BrainError> {
        let resp = self
            .0
            .call(&BusRequest::SubmitProposal { proposal, now_ms })?;
        map_proposal_resp(resp)
    }

    fn send_ipc(
        &mut self,
        message: IpcMessage,
        from_episode_id: &str,
        to_episode_id: &str,
    ) -> Result<IpcMessage, BrainError> {
        let resp = self.0.call(&BusRequest::SendIpc {
            message,
            from_episode_id: from_episode_id.to_string(),
            to_episode_id: to_episode_id.to_string(),
        })?;
        map_ipc_resp(resp)
    }

    fn publish_event(
        &mut self,
        event: EventEnvelope,
        episode_id: &str,
    ) -> Result<BTreeSet<TaintTag>, BrainError> {
        let resp = self.0.call(&BusRequest::PublishEvent {
            event,
            episode_id: episode_id.to_string(),
        })?;
        map_event_resp(resp)
    }
}

/// Framed TCP client adapter for remote agents connecting through `hal-gateway`.
pub struct RemoteGatewayTransport(pub GatewayClient);

impl RemoteGatewayTransport {
    fn unwrap_gw(resp: GatewayResponse) -> Result<BusResponse, BrainError> {
        match resp {
            GatewayResponse::Bus { response } => Ok(response),
            GatewayResponse::Error { code, reason } => Err(BrainError::Bus { code, reason }),
            GatewayResponse::Authenticated { .. } => Err(BrainError::Bus {
                code: "UNEXPECTED_GATEWAY_RESPONSE".to_string(),
                reason: "unexpected Authenticated response for RPC request".to_string(),
            }),
        }
    }
}

impl CognitiveTransport for RemoteGatewayTransport {
    fn submit_proposal(
        &mut self,
        proposal: ActionProposal,
        now_ms: u64,
    ) -> Result<PolicyDecision, BrainError> {
        let resp = Self::unwrap_gw(
            self.0
                .call(&GatewayRequest::SubmitProposal { proposal, now_ms })?,
        )?;
        map_proposal_resp(resp)
    }

    fn send_ipc(
        &mut self,
        message: IpcMessage,
        from_episode_id: &str,
        to_episode_id: &str,
    ) -> Result<IpcMessage, BrainError> {
        let resp = Self::unwrap_gw(self.0.call(&GatewayRequest::SendIpc {
            message,
            from_episode_id: from_episode_id.to_string(),
            to_episode_id: to_episode_id.to_string(),
        })?)?;
        map_ipc_resp(resp)
    }

    fn publish_event(
        &mut self,
        event: EventEnvelope,
        episode_id: &str,
    ) -> Result<BTreeSet<TaintTag>, BrainError> {
        let resp = Self::unwrap_gw(self.0.call(&GatewayRequest::PublishEvent {
            event,
            episode_id: episode_id.to_string(),
        })?)?;
        map_event_resp(resp)
    }
}

/// Unprivileged, secretless cognitive agent instance operating inside Layer 3.
pub struct CognitiveAgent {
    role: AgentRole,
    principal: AgentPrincipal,
    cap_token: CapabilityToken,
    memory: EpisodicMemoryStore,
    seq: u64,
}

impl CognitiveAgent {
    #[must_use]
    pub fn new(
        role: AgentRole,
        principal: AgentPrincipal,
        cap_token: CapabilityToken,
        memory: EpisodicMemoryStore,
    ) -> Self {
        Self {
            role,
            principal,
            cap_token,
            memory,
            seq: 0,
        }
    }

    #[must_use]
    pub fn role(&self) -> AgentRole {
        self.role
    }

    #[must_use]
    pub fn principal(&self) -> &AgentPrincipal {
        &self.principal
    }

    #[must_use]
    pub fn cap_token(&self) -> &CapabilityToken {
        &self.cap_token
    }

    #[must_use]
    pub fn memory(&self) -> &EpisodicMemoryStore {
        &self.memory
    }

    #[must_use]
    pub fn memory_mut(&mut self) -> &mut EpisodicMemoryStore {
        &mut self.memory
    }

    pub fn reload_memory(&mut self) -> Result<(), BrainError> {
        Ok(self.memory.reload()?)
    }

    pub fn record_memory(
        &mut self,
        ts_ms: u64,
        kind: &str,
        summary: &str,
        trigger_event_ids: Vec<String>,
    ) -> Result<(), BrainError> {
        self.memory
            .record(ts_ms, kind, summary, trigger_event_ids)?;
        Ok(())
    }

    /// Publishes a perceived external/local event to `hal-bus` and logs it to episodic memory.
    pub fn perceive_event(
        &mut self,
        transport: &mut dyn CognitiveTransport,
        episode_id: &str,
        event: EventEnvelope,
    ) -> Result<BTreeSet<TaintTag>, BrainError> {
        let ev_id = event.event_id.clone();
        let src = event.source_path.clone();
        let ts = event.ts_ms;
        let taints = transport.publish_event(event, episode_id)?;
        self.memory.record(
            ts,
            "perception",
            &format!("perceived {src} ({ev_id})"),
            vec![ev_id],
        )?;
        Ok(taints)
    }

    /// Invokes brokered LLM inference (secretless!) and parses planned cognitive steps.
    pub fn think_via_broker<E: EgressTransport>(
        &mut self,
        broker: &mut NetBroker<E>,
        episode_id: &str,
        episode_taints: &BTreeSet<TaintTag>,
        prompt: &str,
        now_ms: u64,
    ) -> Result<(Vec<PlannedStep>, BTreeSet<TaintTag>), BrainError> {
        let (steps, tags) = BrokeredLlmClient::plan_via_broker(
            broker,
            &self.principal,
            episode_id,
            episode_taints,
            &self.role.to_string(),
            prompt,
            now_ms,
        )?;
        self.memory.record(
            now_ms,
            "plan",
            &format!("planned {} steps via hal-net-broker", steps.len()),
            Vec::new(),
        )?;
        Ok((steps, tags))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_proposal(
        &mut self,
        transport: &mut dyn CognitiveTransport,
        episode_id: &str,
        target_path: &str,
        action: &str,
        args: Value,
        reason: &str,
        trigger_event_ids: Vec<String>,
        now_ms: u64,
    ) -> Result<PolicyDecision, BrainError> {
        self.seq += 1;
        let proposal = ActionProposal {
            proposal_id: format!("{}_prop_{}", self.principal.agent_id, self.seq),
            episode_id: episode_id.to_string(),
            agent_id: self.principal.agent_id.clone(),
            cap_token: self.cap_token.clone(),
            target_path: target_path.to_string(),
            action: action.to_string(),
            args,
            reason: reason.to_string(),
            trigger_event_ids,
        };
        transport.submit_proposal(proposal, now_ms)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn send_ipc(
        &mut self,
        transport: &mut dyn CognitiveTransport,
        from_episode_id: &str,
        to_episode_id: &str,
        to_agent: &str,
        schema_id: &str,
        payload: Value,
        ts_ms: u64,
    ) -> Result<IpcMessage, BrainError> {
        self.seq += 1;
        let msg = IpcMessage {
            msg_id: format!("{}_ipc_{}", self.principal.agent_id, self.seq),
            from_agent: self.principal.agent_id.clone(),
            to_agent: to_agent.to_string(),
            ts_ms,
            propagated_taints: BTreeSet::new(),
            schema_id: schema_id.to_string(),
            payload,
        };
        transport.send_ipc(msg, from_episode_id, to_episode_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::MockLlmHttpServer;
    use hal_audit::AuditLog;
    use hal_net_broker::{EgressAllowlist, LoopbackHttpTransport, SealedSecret, SecretStore};
    use hal_proto::{sign_token, AgentAuthKind, RiskTier};
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn brokered_llm_planning_injects_key_on_wire_without_exposing_to_brain() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hal_brain_unit_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        let mut llm_srv = MockLlmHttpServer::spawn("sk-broker-only-phase4".into()).unwrap();

        let allowlist = EgressAllowlist::from_file(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy/egress-allowlist.toml"),
        )
        .unwrap();
        let mut secrets = SecretStore::default();
        secrets.insert(
            "llm_api_key",
            SealedSecret::new("Authorization", "Bearer ", "sk-broker-only-phase4"),
        );
        let mut transport = LoopbackHttpTransport::default();
        transport
            .host_overrides
            .insert("api.example-llm.local".to_string(), llm_srv.addr());

        let audit = AuditLog::open(root.join("broker.jsonl")).unwrap();
        let mut broker = NetBroker::new(allowlist, secrets, transport, audit);

        let mut tok = CapabilityToken {
            token_id: "tok_c".into(),
            subject_agent_id: "agent-coder".into(),
            path_patterns: vec!["/work/**".into()],
            allowed_ops: vec!["read".into(), "write".into()],
            max_risk_tier: RiskTier::L1ReversibleCow,
            delegation_depth: 0,
            max_delegation_depth: 1,
            expires_at_ms: 99_000_000,
            rate_limit_per_min: 60,
            token_budget: Some(500),
            hmac_sha256: String::new(),
        };
        sign_token(&mut tok, b"brain-unit-secret");

        let mut agent = CognitiveAgent::new(
            AgentRole::Coder,
            AgentPrincipal {
                agent_id: "agent-coder".into(),
                trust_domain: TrustDomain::WorkspaceWorker,
                auth_kind: AgentAuthKind::LocalNoIpJail,
                parent_agent_id: None,
                peer_cred_or_cert_fp: "uid:1003".into(),
            },
            tok,
            EpisodicMemoryStore::load_or_init(root.join("mem")).unwrap(),
        );

        let (steps, tags) = agent
            .think_via_broker(
                &mut broker,
                "ep_1",
                &BTreeSet::new(),
                "analyze PROMPT_INJECTION_EXFIL",
                1_000,
            )
            .unwrap();
        assert_eq!(steps.len(), 2);
        assert!(tags.contains(&TaintTag::UntrustedWeb));
        assert_eq!(llm_srv.request_count(), 1);
        assert_eq!(llm_srv.valid_auth_count(), 1);
        assert!(agent.memory().contains_summary("planned 2 steps"));

        llm_srv.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }
}
