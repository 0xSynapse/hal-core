use hal_audit::AuditLog;
use hal_os_hal::HalOsError;
use hal_proto::{AgentPrincipal, DualSnapshot, NodeDescriptor, NodeKind, RiskTier, TaintTag};
use hal_workspace::{
    EpisodeWorkspace, LocalDirWorkspaceBackend, WorkspaceDiff, WorkspaceError, WorkspaceManager,
};
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for WorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for WorkError {}

impl From<WorkspaceError> for WorkError {
    fn from(value: WorkspaceError) -> Self {
        match value {
            WorkspaceError::ApprovalRequired(msg) => Self {
                code: "L2_APPROVAL_REQUIRED",
                reason: msg,
            },
            WorkspaceError::EpisodeNotFound(msg) => Self {
                code: "EPISODE_NOT_FOUND",
                reason: msg,
            },
            WorkspaceError::Backend(e) => Self::from(e),
        }
    }
}

impl From<HalOsError> for WorkError {
    fn from(value: HalOsError) -> Self {
        Self {
            code: "WORKSPACE_BACKEND_ERROR",
            reason: value.to_string(),
        }
    }
}

impl From<io::Error> for WorkError {
    fn from(value: io::Error) -> Self {
        Self {
            code: "WORK_IO_ERROR",
            reason: value.to_string(),
        }
    }
}

fn validate_rel_path(rel_path: &str) -> Result<&Path, WorkError> {
    if rel_path.is_empty() || rel_path.contains('\0') {
        return Err(WorkError {
            code: "INVALID_REL_PATH",
            reason: "relative workspace path cannot be empty or contain NUL".to_string(),
        });
    }
    let p = Path::new(rel_path);
    if p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(WorkError {
            code: "INVALID_REL_PATH",
            reason: format!("workspace path '{rel_path}' escapes episode sandbox"),
        });
    }
    Ok(p)
}

/// Layer 2 transactional workspace adapter bridging `CognitiveAgent` L1/L2 file operations
/// onto isolated per-agent `hal-workspace` CoW clones & dual-snapshot rollbacks.
pub struct WorkAdapter {
    manager: WorkspaceManager<LocalDirWorkspaceBackend>,
}

impl WorkAdapter {
    #[must_use]
    pub fn new(backend: LocalDirWorkspaceBackend, audit: AuditLog) -> Self {
        Self {
            manager: WorkspaceManager::new(backend, audit),
        }
    }

    #[must_use]
    pub fn descriptors() -> Vec<NodeDescriptor> {
        vec![
            NodeDescriptor {
                path: "/work/agents/*/episodes/*/fs".to_string(),
                kind: NodeKind::Dual,
                risk_tier: RiskTier::L1ReversibleCow,
                default_taint: None,
                reversible: true,
                description: "Per-agent Copy-on-Write episode filesystem subtree".to_string(),
            },
            NodeDescriptor {
                path: "/work/agents/*/episodes/*/exec".to_string(),
                kind: NodeKind::Dual,
                risk_tier: RiskTier::L1ReversibleCow,
                default_taint: Some(TaintTag::UntrustedCode),
                reversible: true,
                description: "No-IP build/test execution inside CoW episode sandbox".to_string(),
            },
            NodeDescriptor {
                path: "/work/agents/*/episodes/*/merge".to_string(),
                kind: NodeKind::Effector,
                risk_tier: RiskTier::L2IrreversibleOrExternal,
                default_taint: None,
                reversible: false,
                description: "Promote verified CoW episode changes into clean base (L2 approval)"
                    .to_string(),
            },
        ]
    }

    #[must_use]
    pub fn manager(&self) -> &WorkspaceManager<LocalDirWorkspaceBackend> {
        &self.manager
    }

    #[must_use]
    pub fn manager_mut(&mut self) -> &mut WorkspaceManager<LocalDirWorkspaceBackend> {
        &mut self.manager
    }

    #[must_use]
    pub fn base_workspace_dir(&self) -> PathBuf {
        self.manager.backend().base_workspace_dir()
    }

    #[must_use]
    pub fn base_memory_dir(&self) -> PathBuf {
        self.manager.backend().base_memory_dir()
    }

    pub fn episode_workspace_dir(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<PathBuf, WorkError> {
        Ok(self
            .manager
            .backend()
            .episode_workspace_dir(agent_id, episode_id)?)
    }

    pub fn episode_memory_dir(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<PathBuf, WorkError> {
        Ok(self
            .manager
            .backend()
            .episode_memory_dir(agent_id, episode_id)?)
    }

    pub fn begin_episode(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        now_ms: u64,
    ) -> Result<EpisodeWorkspace, WorkError> {
        Ok(self.manager.begin_episode(principal, episode_id, now_ms)?)
    }

    pub fn snapshot_before_l1(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        tag: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<DualSnapshot, WorkError> {
        Ok(self
            .manager
            .snapshot_before_l1(principal, episode_id, tag, reason, now_ms)?)
    }

    pub fn write_file(
        &self,
        agent_id: &str,
        episode_id: &str,
        rel_path: &str,
        content: &str,
    ) -> Result<(), WorkError> {
        let rel = validate_rel_path(rel_path)?;
        let full = self.episode_workspace_dir(agent_id, episode_id)?.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(full, content)?;
        Ok(())
    }

    pub fn delete_file(
        &self,
        agent_id: &str,
        episode_id: &str,
        rel_path: &str,
    ) -> Result<(), WorkError> {
        let rel = validate_rel_path(rel_path)?;
        let full = self.episode_workspace_dir(agent_id, episode_id)?.join(rel);
        if full.exists() {
            std::fs::remove_file(full)?;
        }
        Ok(())
    }

    pub fn read_file(
        &self,
        agent_id: &str,
        episode_id: &str,
        rel_path: &str,
    ) -> Result<String, WorkError> {
        let rel = validate_rel_path(rel_path)?;
        let full = self.episode_workspace_dir(agent_id, episode_id)?.join(rel);
        Ok(std::fs::read_to_string(full)?)
    }

    pub fn diff_against_base(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<WorkspaceDiff, WorkError> {
        Ok(self
            .manager
            .backend()
            .diff_against_base(agent_id, episode_id)?)
    }

    pub fn rollback_dual_snapshot(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        tag: &str,
        now_ms: u64,
    ) -> Result<(), WorkError> {
        Ok(self
            .manager
            .rollback_dual_snapshot(principal, episode_id, tag, now_ms)?)
    }

    pub fn commit_episode(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        approval_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(), WorkError> {
        self.manager
            .commit_episode(principal, episode_id, approval_id, now_ms)?;
        self.manager
            .backend()
            .merge_to_base(&principal.agent_id, episode_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_proto::{AgentAuthKind, TrustDomain};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn transactional_edits_rollback_and_require_l2_approval_to_merge() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hal_work_unit_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        let backend = LocalDirWorkspaceBackend::new(&root).unwrap();
        std::fs::write(backend.base_workspace_dir().join("nav.toml"), "mode=nominal\n").unwrap();
        std::fs::write(backend.base_workspace_dir().join("guard.cfg"), "enabled=1\n").unwrap();
        let audit = AuditLog::open(root.join("work-audit.jsonl")).unwrap();
        let mut work = WorkAdapter::new(backend, audit);

        let coder = AgentPrincipal {
            agent_id: "agent-coder".into(),
            trust_domain: TrustDomain::WorkspaceWorker,
            auth_kind: AgentAuthKind::LocalNoIpJail,
            parent_agent_id: None,
            peer_cred_or_cert_fp: "uid:1003".into(),
        };

        work.begin_episode(&coder, "ep_unit", 1000).unwrap();
        work.snapshot_before_l1(&coder, "ep_unit", "step_01", "pre-edit", 1100)
            .unwrap();

        assert_eq!(
            work.write_file("agent-coder", "ep_unit", "../escape.txt", "x")
                .unwrap_err()
                .code,
            "INVALID_REL_PATH"
        );
        work.write_file("agent-coder", "ep_unit", "nav.toml", "mode=broken\n")
            .unwrap();
        work.delete_file("agent-coder", "ep_unit", "guard.cfg")
            .unwrap();
        assert!(!work
            .diff_against_base("agent-coder", "ep_unit")
            .unwrap()
            .is_empty());

        // Unapproved merge rejected; base unchanged
        assert_eq!(
            work.commit_episode(&coder, "ep_unit", None, 1200)
                .unwrap_err()
                .code,
            "L2_APPROVAL_REQUIRED"
        );
        assert_eq!(
            std::fs::read_to_string(work.base_workspace_dir().join("nav.toml")).unwrap(),
            "mode=nominal\n"
        );

        // Rollback restores modified + deleted files cleanly
        work.rollback_dual_snapshot(&coder, "ep_unit", "step_01", 1300)
            .unwrap();
        assert!(work
            .diff_against_base("agent-coder", "ep_unit")
            .unwrap()
            .is_empty());
        assert_eq!(
            work.read_file("agent-coder", "ep_unit", "guard.cfg").unwrap(),
            "enabled=1\n"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
