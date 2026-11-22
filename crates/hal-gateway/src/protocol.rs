use hal_proto::wire::BusResponse;
use hal_proto::{
    hex_decode, hex_encode, ActionProposal, AgentPrincipal, CapabilityToken, EventEnvelope,
    IpcMessage,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const CERT_PROOF_DOMAIN_SEP: &[u8] = b"hal-gateway-proof-v1:";

fn build_proof_input(agent_id: &str, cert_sha256: &str, nonce: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CERT_PROOF_DOMAIN_SEP.len() + agent_id.len() + cert_sha256.len() + nonce.len() + 2,
    );
    out.extend_from_slice(CERT_PROOF_DOMAIN_SEP);
    out.extend_from_slice(agent_id.as_bytes());
    out.push(b':');
    out.extend_from_slice(cert_sha256.as_bytes());
    out.push(b':');
    out.extend_from_slice(nonce.as_bytes());
    out
}

/// Computes an mTLS/WireGuard peer proof-of-possession HMAC over client identity + nonce.
#[must_use]
pub fn compute_cert_proof(key: &[u8], agent_id: &str, cert_sha256: &str, nonce: &str) -> String {
    let payload = build_proof_input(agent_id, cert_sha256, nonce);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&payload);
    hex_encode(&mac.finalize().into_bytes())
}

/// Verifies peer proof-of-possession HMAC in constant time.
#[must_use]
pub fn verify_cert_proof(
    key: &[u8],
    agent_id: &str,
    cert_sha256: &str,
    nonce: &str,
    proof_hex: &str,
) -> bool {
    let Some(sig) = hex_decode(proof_hex) else {
        return false;
    };
    if sig.len() != 32 {
        return false;
    }
    let payload = build_proof_input(agent_id, cert_sha256, nonce);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(&payload);
    mac.verify_slice(&sig).is_ok()
}

/// Initial remote authentication payload sent to `hal-gateway`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteAuthHandshake {
    pub claimed_agent_id: String,
    pub cert_sha256: String,
    pub client_nonce: String,
    pub cert_proof_hmac: String,
    pub cap_token: CapabilityToken,
    pub now_ms: u64,
}

/// Framed RPC messages accepted over `hal-gateway` TCP ingress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GatewayRequest {
    Authenticate {
        handshake: RemoteAuthHandshake,
    },
    Ping,
    SubmitProposal {
        proposal: ActionProposal,
        now_ms: u64,
    },
    SendIpc {
        message: IpcMessage,
        from_episode_id: String,
        to_episode_id: String,
    },
    PublishEvent {
        event: EventEnvelope,
        episode_id: String,
    },
}

/// Framed RPC responses emitted by `hal-gateway`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GatewayResponse {
    Authenticated {
        principal: AgentPrincipal,
        session_id: String,
    },
    Bus {
        response: BusResponse,
    },
    Error {
        code: String,
        reason: String,
    },
}
