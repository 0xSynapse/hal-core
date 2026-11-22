use crate::config::{BridgeConfig, BridgeConfigError};
use hal_gateway::{compute_cert_proof, GatewayClient, GatewayRequest, GatewayResponse, RemoteAuthHandshake};
use hal_proto::wire::BusResponse;
use hal_proto::{ActionProposal, AgentPrincipal, EventEnvelope, IpcMessage, TaintTag, TrustLevel};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NONCE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum BridgeError {
    Io(io::Error),
    Config(BridgeConfigError),
    Gateway { code: String, reason: String },
    Protocol(String),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "bridge I/O error: {e}"),
            Self::Config(e) => write!(f, "{e}"),
            Self::Gateway { code, reason } => write!(f, "hal-gateway error ({code}): {reason}"),
            Self::Protocol(msg) => write!(f, "bridge protocol error: {msg}"),
        }
    }
}

impl std::error::Error for BridgeError {}

impl From<io::Error> for BridgeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<BridgeConfigError> for BridgeError {
    fn from(value: BridgeConfigError) -> Self {
        Self::Config(value)
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unwrap_bus_response(resp: GatewayResponse) -> Result<BusResponse, BridgeError> {
    match resp {
        GatewayResponse::Bus { response } => Ok(response),
        GatewayResponse::Error { code, reason } => Err(BridgeError::Gateway { code, reason }),
        other => Err(BridgeError::Protocol(format!(
            "unexpected gateway response: {other:?}"
        ))),
    }
}

/// Authenticated remote client session from laptop coding agents (`Aegis OS`) to `HAL Core`.
pub struct BridgeSession {
    client: GatewayClient,
    config: BridgeConfig,
    principal: AgentPrincipal,
    session_id: String,
    proposal_seq: u64,
    msg_seq: u64,
    event_seq: u64,
}

impl BridgeSession {
    pub fn connect(config: BridgeConfig) -> Result<Self, BridgeError> {
        let mut client = GatewayClient::connect(config.gateway_addr)?;
        let now_ms = now_unix_ms();
        let seq = NONCE_SEQ.fetch_add(1, Ordering::Relaxed);
        let nonce = format!("br-{}-{now_ms}-{seq}", std::process::id());
        let cert_proof_hmac = compute_cert_proof(
            &config.peer_proof_key,
            &config.agent_id,
            &config.cert_sha256,
            &nonce,
        );
        let handshake = RemoteAuthHandshake {
            claimed_agent_id: config.agent_id.clone(),
            cert_sha256: config.cert_sha256.clone(),
            client_nonce: nonce,
            cert_proof_hmac,
            cap_token: config.cap_token.clone(),
            now_ms,
        };
        match client.authenticate(handshake)? {
            GatewayResponse::Authenticated {
                principal,
                session_id,
            } => Ok(Self {
                client,
                config,
                principal,
                session_id,
                proposal_seq: 0,
                msg_seq: 0,
                event_seq: 0,
            }),
            GatewayResponse::Error { code, reason } => Err(BridgeError::Gateway { code, reason }),
            other => Err(BridgeError::Protocol(format!(
                "unexpected authenticate response: {other:?}"
            ))),
        }
    }

    #[must_use]
    pub fn principal(&self) -> &AgentPrincipal {
        &self.principal
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn default_episode_id(&self) -> &str {
        &self.config.default_episode_id
    }

    pub fn ping(&mut self) -> Result<BusResponse, BridgeError> {
        let resp = self.client.call(&GatewayRequest::Ping)?;
        unwrap_bus_response(resp)
    }

    pub fn submit_proposal(
        &mut self,
        episode_id: Option<&str>,
        target_path: &str,
        action: &str,
        args: Value,
        reason: &str,
        trigger_event_ids: Vec<String>,
    ) -> Result<BusResponse, BridgeError> {
        self.proposal_seq += 1;
        let now_ms = now_unix_ms();
        let proposal = ActionProposal {
            proposal_id: format!("p_{}_{}", self.session_id, self.proposal_seq),
            episode_id: episode_id
                .unwrap_or(&self.config.default_episode_id)
                .to_string(),
            agent_id: self.principal.agent_id.clone(),
            cap_token: self.config.cap_token.clone(),
            target_path: target_path.to_string(),
            action: action.to_string(),
            args,
            reason: reason.to_string(),
            trigger_event_ids,
        };
        let resp = self
            .client
            .call(&GatewayRequest::SubmitProposal { proposal, now_ms })?;
        unwrap_bus_response(resp)
    }

    pub fn vault_read(
        &mut self,
        path: &str,
        reason: &str,
        episode_id: Option<&str>,
    ) -> Result<BusResponse, BridgeError> {
        validate_vault_path(path)?;
        self.submit_proposal(episode_id, path, "read", Value::Object(Default::default()), reason, Vec::new())
    }

    pub fn send_ipc(
        &mut self,
        to_agent: &str,
        schema_id: &str,
        payload: Value,
        from_episode_id: Option<&str>,
        to_episode_id: &str,
    ) -> Result<BusResponse, BridgeError> {
        self.msg_seq += 1;
        let now_ms = now_unix_ms();
        let from_ep = from_episode_id
            .unwrap_or(&self.config.default_episode_id)
            .to_string();
        let message = IpcMessage {
            msg_id: format!("ipc_{}_{}", self.session_id, self.msg_seq),
            from_agent: self.principal.agent_id.clone(),
            to_agent: to_agent.to_string(),
            ts_ms: now_ms,
            propagated_taints: BTreeSet::new(),
            schema_id: schema_id.to_string(),
            payload,
        };
        let resp = self.client.call(&GatewayRequest::SendIpc {
            message,
            from_episode_id: from_ep,
            to_episode_id: to_episode_id.to_string(),
        })?;
        unwrap_bus_response(resp)
    }

    pub fn publish_event(
        &mut self,
        source_path: &str,
        payload: Value,
        episode_id: Option<&str>,
    ) -> Result<BusResponse, BridgeError> {
        self.event_seq += 1;
        let now_ms = now_unix_ms();
        let mut taints = BTreeSet::new();
        taints.insert(TaintTag::UntrustedMsg);
        let event = EventEnvelope {
            event_id: format!("evt_{}_{}", self.session_id, self.event_seq),
            ts_ms: now_ms,
            source_path: source_path.to_string(),
            producer_actor: self.principal.agent_id.clone(),
            trust_level: TrustLevel::UntrustedExternal,
            taint_tags: taints,
            payload,
        };
        let ep = episode_id
            .unwrap_or(&self.config.default_episode_id)
            .to_string();
        let resp = self
            .client
            .call(&GatewayRequest::PublishEvent { event, episode_id: ep })?;
        unwrap_bus_response(resp)
    }
}

pub fn validate_vault_path(path: &str) -> Result<(), BridgeError> {
    if !path.starts_with("/vault/")
        || path.contains('\0')
        || path.ends_with('/')
        || path
            .split('/')
            .skip(1)
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return Err(BridgeError::Protocol(format!(
            "invalid vault path '{path}': must start with '/vault/' without traversal or empty segments"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_vault_path;

    #[test]
    fn validates_vault_paths_and_blocks_traversal() {
        assert!(validate_vault_path("/vault/docs/plan.md").is_ok());
        assert!(validate_vault_path("/vault/../etc/passwd").is_err());
        assert!(validate_vault_path("/vault/").is_err());
        assert!(validate_vault_path("/habitat/entry/lock").is_err());
        assert!(validate_vault_path("/vault/a//b").is_err());
    }
}
