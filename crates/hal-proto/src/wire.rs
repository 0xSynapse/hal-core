use crate::token::DelegationSpec;
use crate::types::{
    ActionProposal, AgentPrincipal, AgentStatusEntry, CapabilityToken, EventEnvelope, IpcMessage,
    PendingApproval, PolicyDecision, ResourceLease, SystemMode, TaintTag,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

/// Codec tag identifying UTF-8 JSON frame payloads.
pub const CODEC_JSON: u8 = 0x01;

/// Maximum permitted frame payload length (1 MiB, including codec tag byte).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Control-plane requests sent over Unix Domain Sockets to `hal-bus`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BusRequest {
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
    AcquireLease {
        resource_path: String,
        priority: u8,
        ttl_ms: u64,
        now_ms: u64,
        is_oob: bool,
    },
    ReleaseLease {
        lease_id: String,
    },
    QueryLease {
        resource_path: String,
        now_ms: u64,
    },
    RegisterAgent {
        principal: AgentPrincipal,
    },
    FreezeAgent {
        target_agent_id: String,
        reason: String,
    },
    UnfreezeAgent {
        target_agent_id: String,
    },
    SetSystemMode {
        mode: SystemMode,
        reason: String,
    },
    DelegateToken {
        parent_token: CapabilityToken,
        spec: DelegationSpec,
        now_ms: u64,
    },
    GetEpisodeTaints {
        agent_id: String,
        episode_id: String,
    },
    ListAgents,
    ListPendingApprovals,
    ResolveApproval {
        approval_id: String,
        approve: bool,
        note: String,
        now_ms: u64,
    },
    RevokeAgent {
        target_agent_id: String,
        reason: String,
    },
    GatewaySubmitProposal {
        remote_principal: AgentPrincipal,
        proposal: ActionProposal,
        now_ms: u64,
    },
    GatewaySendIpc {
        remote_principal: AgentPrincipal,
        message: IpcMessage,
        from_episode_id: String,
        to_episode_id: String,
    },
    GatewayPublishEvent {
        remote_principal: AgentPrincipal,
        event: EventEnvelope,
        episode_id: String,
    },
}

/// Responses returned by `hal-bus` over Unix Domain Sockets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BusResponse {
    Pong {
        principal: AgentPrincipal,
        system_mode: SystemMode,
    },
    ProposalDecision {
        decision: PolicyDecision,
    },
    IpcDelivered {
        message: IpcMessage,
    },
    IpcDenied {
        code: String,
        reason: String,
    },
    EventRecorded {
        episode_taints: BTreeSet<TaintTag>,
    },
    LeaseGranted {
        lease: ResourceLease,
        preempted_lease_id: Option<String>,
    },
    LeaseDenied {
        code: String,
        reason: String,
    },
    LeaseReleased {
        released: bool,
    },
    LeaseStatus {
        lease: Option<ResourceLease>,
    },
    AgentRegistered {
        agent_id: String,
    },
    AgentFrozen {
        agent_id: String,
        reason: String,
    },
    AgentUnfrozen {
        agent_id: String,
    },
    ModeUpdated {
        mode: SystemMode,
    },
    TokenDelegated {
        token: CapabilityToken,
    },
    EpisodeTaints {
        agent_id: String,
        episode_id: String,
        taints: BTreeSet<TaintTag>,
    },
    AgentList {
        agents: Vec<AgentStatusEntry>,
        system_mode: SystemMode,
    },
    PendingApprovals {
        approvals: Vec<PendingApproval>,
    },
    ApprovalResolved {
        approval: Box<PendingApproval>,
    },
    AgentRevoked {
        agent_id: String,
        reason: String,
    },
    Error {
        code: String,
        reason: String,
    },
}

/// Writes a `[4-byte BE length][1-byte codec tag][JSON bytes]` frame to `writer`.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let total_len = payload
        .len()
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame size overflow"))?;
    if total_len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame length {total_len} exceeds MAX_FRAME_BYTES ({MAX_FRAME_BYTES})"),
        ));
    }
    let len_be = (total_len as u32).to_be_bytes();
    writer.write_all(&len_be)?;
    writer.write_all(&[CODEC_JSON])?;
    writer.write_all(&payload)?;
    writer.flush()
}

/// Reads a single `[4-byte BE length][1-byte codec tag][JSON bytes]` frame from `reader`.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let total_len = u32::from_be_bytes(len_buf) as usize;
    if total_len == 0 || total_len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid frame length {total_len}"),
        ));
    }
    let mut buf = vec![0u8; total_len];
    reader.read_exact(&mut buf)?;
    if buf[0] != CODEC_JSON {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported frame codec tag 0x{:02x}", buf[0]),
        ));
    }
    serde_json::from_slice(&buf[1..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_oversize_rejection() {
        let mut wire_bytes = Vec::new();
        let req = BusRequest::Ping;
        write_frame(&mut wire_bytes, &req).unwrap();
        let decoded: BusRequest = read_frame(&mut wire_bytes.as_slice()).unwrap();
        assert_eq!(decoded, req);

        let bad_len = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        let err = read_frame::<_, BusRequest>(&mut bad_len.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
