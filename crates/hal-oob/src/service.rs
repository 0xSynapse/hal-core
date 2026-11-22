use hal_audit::{read_records_from_seq, verify_file, AuditError, VerifyReport};
use hal_bus::BusClient;
use hal_os_hal::{HalOsError, WorkspaceBackend};
use hal_proto::wire::{BusRequest, BusResponse};
use hal_proto::{
    AgentStatusEntry, AuditRecord, PendingApproval, ResourceLease, SystemMode, GENESIS_PREV_HASH,
};
use hal_workspace::LocalDirWorkspaceBackend;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum OobError {
    Io(io::Error),
    Audit(AuditError),
    Workspace(HalOsError),
    Bus { code: String, reason: String },
    InvalidConfig { code: &'static str, reason: String },
}

impl fmt::Display for OobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "OOB I/O error: {e}"),
            Self::Audit(e) => write!(f, "OOB audit error: {e}"),
            Self::Workspace(e) => write!(f, "OOB workspace error: {e}"),
            Self::Bus { code, reason } => write!(f, "hal-bus error ({code}): {reason}"),
            Self::InvalidConfig { code, reason } => write!(f, "{code}: {reason}"),
        }
    }
}

impl std::error::Error for OobError {}

impl From<io::Error> for OobError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AuditError> for OobError {
    fn from(value: AuditError) -> Self {
        Self::Audit(value)
    }
}

impl From<HalOsError> for OobError {
    fn from(value: HalOsError) -> Self {
        Self::Workspace(value)
    }
}

/// High-level out-of-band status snapshot presented on `mgmt0` and `halctl status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OobStatusSummary {
    pub system_mode: SystemMode,
    pub agent_count: usize,
    pub frozen_count: usize,
    pub pending_approval_count: usize,
    pub audit_records: u64,
    pub audit_head_hash: String,
}

/// Out-of-band controller client mediating human sovereignty actions over `oob.sock`,
/// read-only `hal-audit` verification, and dual-snapshot workspace rollback.
#[derive(Debug, Clone)]
pub struct OobController {
    bus_oob_socket: PathBuf,
    audit_path: PathBuf,
}

impl OobController {
    #[must_use]
    pub fn new(bus_oob_socket: impl AsRef<Path>, audit_path: impl AsRef<Path>) -> Self {
        Self {
            bus_oob_socket: bus_oob_socket.as_ref().to_path_buf(),
            audit_path: audit_path.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn bus_oob_socket(&self) -> &Path {
        &self.bus_oob_socket
    }

    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    fn call_bus(&self, req: &BusRequest) -> Result<BusResponse, OobError> {
        let mut client = BusClient::connect(&self.bus_oob_socket)?;
        let resp = client.call(req)?;
        if let BusResponse::Error { code, reason } = resp {
            return Err(OobError::Bus { code, reason });
        }
        Ok(resp)
    }

    pub fn status(&self) -> Result<OobStatusSummary, OobError> {
        let (agents, system_mode) = self.list_agents()?;
        let approvals = self.list_approvals()?;
        let frozen_count = agents.iter().filter(|a| a.frozen_reason.is_some()).count();
        let pending_approval_count = approvals
            .iter()
            .filter(|a| a.status == hal_proto::ApprovalStatus::Pending)
            .count();

        let (audit_records, audit_head_hash) = if self.audit_path.exists() {
            let rpt = verify_file(&self.audit_path)?;
            (rpt.record_count, rpt.head_hash)
        } else {
            (0, GENESIS_PREV_HASH.to_string())
        };

        Ok(OobStatusSummary {
            system_mode,
            agent_count: agents.len(),
            frozen_count,
            pending_approval_count,
            audit_records,
            audit_head_hash,
        })
    }

    pub fn list_agents(&self) -> Result<(Vec<AgentStatusEntry>, SystemMode), OobError> {
        match self.call_bus(&BusRequest::ListAgents)? {
            BusResponse::AgentList {
                agents,
                system_mode,
            } => Ok((agents, system_mode)),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn freeze_agent(&self, agent_id: &str, reason: &str) -> Result<String, OobError> {
        match self.call_bus(&BusRequest::FreezeAgent {
            target_agent_id: agent_id.to_string(),
            reason: reason.to_string(),
        })? {
            BusResponse::AgentFrozen { agent_id, .. } => Ok(agent_id),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn unfreeze_agent(&self, agent_id: &str) -> Result<String, OobError> {
        match self.call_bus(&BusRequest::UnfreezeAgent {
            target_agent_id: agent_id.to_string(),
        })? {
            BusResponse::AgentUnfrozen { agent_id } => Ok(agent_id),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn revoke_agent(&self, agent_id: &str, reason: &str) -> Result<String, OobError> {
        match self.call_bus(&BusRequest::RevokeAgent {
            target_agent_id: agent_id.to_string(),
            reason: reason.to_string(),
        })? {
            BusResponse::AgentRevoked { agent_id, .. } => Ok(agent_id),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn set_mode(&self, mode: SystemMode, reason: &str) -> Result<SystemMode, OobError> {
        match self.call_bus(&BusRequest::SetSystemMode {
            mode,
            reason: reason.to_string(),
        })? {
            BusResponse::ModeUpdated { mode } => Ok(mode),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn list_approvals(&self) -> Result<Vec<PendingApproval>, OobError> {
        match self.call_bus(&BusRequest::ListPendingApprovals)? {
            BusResponse::PendingApprovals { approvals } => Ok(approvals),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn resolve_approval(
        &self,
        approval_id: &str,
        approve: bool,
        note: &str,
        now_ms: u64,
    ) -> Result<PendingApproval, OobError> {
        match self.call_bus(&BusRequest::ResolveApproval {
            approval_id: approval_id.to_string(),
            approve,
            note: note.to_string(),
            now_ms,
        })? {
            BusResponse::ApprovalResolved { approval } => Ok(*approval),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn preempt_lease(
        &self,
        resource_path: &str,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<(ResourceLease, Option<String>), OobError> {
        match self.call_bus(&BusRequest::AcquireLease {
            resource_path: resource_path.to_string(),
            priority: u8::MAX,
            ttl_ms,
            now_ms,
            is_oob: true,
        })? {
            BusResponse::LeaseGranted {
                lease,
                preempted_lease_id,
            } => Ok((lease, preempted_lease_id)),
            BusResponse::LeaseDenied { code, reason } => Err(OobError::Bus { code, reason }),
            other => Err(unexpected_bus(other)),
        }
    }

    pub fn verify_audit(&self) -> Result<VerifyReport, OobError> {
        Ok(verify_file(&self.audit_path)?)
    }

    pub fn read_audit_records(&self, after_seq: u64) -> Result<Vec<AuditRecord>, OobError> {
        Ok(read_records_from_seq(&self.audit_path, after_seq)?)
    }

    /// Atomically rolls back BOTH workspace files and AI episodic memory for an agent episode.
    pub fn rollback_agent_workspace(
        &self,
        workspace_root: impl AsRef<Path>,
        agent_id: &str,
        episode_id: &str,
        tag: &str,
    ) -> Result<(), OobError> {
        let backend = LocalDirWorkspaceBackend::new(workspace_root)?;
        // Validate leaf paths through backend helpers before building dataset identifiers
        let _ = backend.episode_workspace_dir(agent_id, episode_id)?;
        let _ = backend.episode_memory_dir(agent_id, episode_id)?;
        let ws_ds = format!("halpool/workspaces/active/{agent_id}/{episode_id}");
        let mem_ds = format!("halpool/memory/active/{agent_id}/{episode_id}");
        backend.rollback_dual_snapshot(&ws_ds, &mem_ds, tag)?;
        Ok(())
    }
}

fn unexpected_bus(resp: BusResponse) -> OobError {
    OobError::Bus {
        code: "UNEXPECTED_BUS_RESPONSE".to_string(),
        reason: format!("unexpected bus response: {resp:?}"),
    }
}
