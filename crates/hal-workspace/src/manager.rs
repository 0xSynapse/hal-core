use hal_audit::{AuditInput, AuditLog};
use hal_os_hal::{DualSnapshotRequest, HalOsError, WorkspaceBackend};
use hal_proto::{AgentPrincipal, DualSnapshot};
use std::collections::HashMap;
use std::fmt;

/// Active workspace + AI memory dataset pair tracked for a single episode.
#[derive(Debug, Clone)]
pub struct EpisodeWorkspace {
    pub agent_id: String,
    pub episode_id: String,
    pub workspace_dataset: String,
    pub memory_dataset: String,
    pub snapshots: Vec<DualSnapshot>,
}

#[derive(Debug)]
pub enum WorkspaceError {
    Backend(HalOsError),
    EpisodeNotFound(String),
    ApprovalRequired(String),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "workspace backend error: {e}"),
            Self::EpisodeNotFound(k) => write!(f, "workspace episode '{k}' not found"),
            Self::ApprovalRequired(msg) => write!(f, "L2_APPROVAL_REQUIRED: {msg}"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<HalOsError> for WorkspaceError {
    fn from(value: HalOsError) -> Self {
        Self::Backend(value)
    }
}

/// Deterministic lifecycle controller for per-agent CoW clones & dual-snapshot transactions.
pub struct WorkspaceManager<B: WorkspaceBackend> {
    backend: B,
    episodes: HashMap<(String, String), EpisodeWorkspace>,
    audit: AuditLog,
}

impl<B: WorkspaceBackend> WorkspaceManager<B> {
    #[must_use]
    pub fn new(backend: B, audit: AuditLog) -> Self {
        Self {
            backend,
            episodes: HashMap::new(),
            audit,
        }
    }

    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    #[must_use]
    pub fn episode(&self, agent_id: &str, episode_id: &str) -> Option<&EpisodeWorkspace> {
        self.episodes
            .get(&(agent_id.to_string(), episode_id.to_string()))
    }

    fn record_audit(
        &mut self,
        now_ms: u64,
        principal: &AgentPrincipal,
        episode_id: &str,
        action: &str,
        summary: String,
        snap_id: Option<String>,
    ) {
        let _ = self.audit.append(AuditInput {
            ts_ms: now_ms,
            principal: principal.clone(),
            episode_id: episode_id.to_string(),
            target_path: format!("/work/agents/{}/episodes/{episode_id}", principal.agent_id),
            action: action.to_string(),
            trigger_event_ids: Vec::new(),
            proposal_id: None,
            decision_summary: summary,
            workspace_snapshot_id: snap_id,
        });
    }

    /// Clones fresh isolated workspace + AI memory datasets for `(principal.agent_id, episode_id)`.
    pub fn begin_episode(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        now_ms: u64,
    ) -> Result<EpisodeWorkspace, WorkspaceError> {
        let (ws_ds, mem_ds) = self
            .backend
            .clone_episode_datasets(&principal.agent_id, episode_id)?;
        let ep = EpisodeWorkspace {
            agent_id: principal.agent_id.clone(),
            episode_id: episode_id.to_string(),
            workspace_dataset: ws_ds.clone(),
            memory_dataset: mem_ds.clone(),
            snapshots: Vec::new(),
        };
        self.episodes.insert(
            (principal.agent_id.clone(), episode_id.to_string()),
            ep.clone(),
        );
        self.record_audit(
            now_ms,
            principal,
            episode_id,
            "begin_episode",
            format!("Cloned(ws={ws_ds}, mem={mem_ds})"),
            None,
        );
        Ok(ep)
    }

    /// Atomically snapshots both workspace disk and AI memory state before an `L1` mutation.
    pub fn snapshot_before_l1(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        tag: &str,
        reason: &str,
        now_ms: u64,
    ) -> Result<DualSnapshot, WorkspaceError> {
        let key = (principal.agent_id.clone(), episode_id.to_string());
        let ep = self
            .episodes
            .get(&key)
            .ok_or_else(|| WorkspaceError::EpisodeNotFound(format!("{}:{}", key.0, key.1)))?;
        let snap = self.backend.create_dual_snapshot(&DualSnapshotRequest {
            workspace_dataset: &ep.workspace_dataset,
            memory_dataset: &ep.memory_dataset,
            snapshot_tag: tag,
            reason,
            agent_id: &principal.agent_id,
            episode_id,
            now_ms,
        })?;
        self.episodes
            .get_mut(&key)
            .expect("episode just verified")
            .snapshots
            .push(snap.clone());
        self.record_audit(
            now_ms,
            principal,
            episode_id,
            "snapshot_before_l1",
            format!("DualSnapshot({tag}: {reason})"),
            Some(tag.to_string()),
        );
        Ok(snap)
    }

    /// Rolls back BOTH workspace disk and AI episodic memory to the exact TXG/slice `tag`.
    pub fn rollback_dual_snapshot(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        tag: &str,
        now_ms: u64,
    ) -> Result<(), WorkspaceError> {
        let key = (principal.agent_id.clone(), episode_id.to_string());
        let (ws_ds, mem_ds) = {
            let ep = self
                .episodes
                .get(&key)
                .ok_or_else(|| WorkspaceError::EpisodeNotFound(format!("{}:{}", key.0, key.1)))?;
            (ep.workspace_dataset.clone(), ep.memory_dataset.clone())
        };
        self.backend.rollback_dual_snapshot(&ws_ds, &mem_ds, tag)?;
        self.record_audit(
            now_ms,
            principal,
            episode_id,
            "rollback_dual_snapshot",
            format!("DualRollback({tag})"),
            Some(tag.to_string()),
        );
        Ok(())
    }

    /// Authorizes promoting/committing episode changes ONLY after human `L2` `approval_id`.
    pub fn commit_episode(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        approval_id: Option<&str>,
        now_ms: u64,
    ) -> Result<(), WorkspaceError> {
        let key = (principal.agent_id.clone(), episode_id.to_string());
        if !self.episodes.contains_key(&key) {
            return Err(WorkspaceError::EpisodeNotFound(format!(
                "{}:{}",
                key.0, key.1
            )));
        }
        let Some(appr) = approval_id.filter(|s| !s.trim().is_empty()) else {
            self.record_audit(
                now_ms,
                principal,
                episode_id,
                "commit_episode",
                "Deny(L2_APPROVAL_REQUIRED: commit to base requires OOB approval_id)".to_string(),
                None,
            );
            return Err(WorkspaceError::ApprovalRequired(
                "merging CoW episode into base requires an OOB L2 approval_id".to_string(),
            ));
        };
        self.record_audit(
            now_ms,
            principal,
            episode_id,
            "commit_episode",
            format!("CommitApproved(approval_id={appr})"),
            None,
        );
        Ok(())
    }

    /// Destroys temporary per-episode datasets and logs cleanup.
    pub fn destroy_episode(
        &mut self,
        principal: &AgentPrincipal,
        episode_id: &str,
        now_ms: u64,
    ) -> Result<(), WorkspaceError> {
        let key = (principal.agent_id.clone(), episode_id.to_string());
        let ep = self
            .episodes
            .remove(&key)
            .ok_or_else(|| WorkspaceError::EpisodeNotFound(format!("{}:{}", key.0, key.1)))?;
        self.backend
            .destroy_episode_datasets(&ep.workspace_dataset, &ep.memory_dataset)?;
        self.record_audit(
            now_ms,
            principal,
            episode_id,
            "destroy_episode",
            format!("Destroyed(ws={}, mem={})", ep.workspace_dataset, ep.memory_dataset),
            None,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_cow::LocalDirWorkspaceBackend;
    use hal_proto::{AgentAuthKind, TrustDomain};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "hal_ws_{label}_{}_{}",
            std::process::id(),
            nanos
        ))
    }

    fn coder_principal() -> AgentPrincipal {
        AgentPrincipal {
            agent_id: "agent-coder".to_string(),
            trust_domain: TrustDomain::WorkspaceWorker,
            auth_kind: AgentAuthKind::LocalNoIpJail,
            parent_agent_id: None,
            peer_cred_or_cert_fp: "uid:1003".to_string(),
        }
    }

    #[test]
    fn real_dir_dual_rollback_reverts_corrupted_files_and_false_memory_without_drift() {
        let root = tmp_dir("rollback");
        let backend = LocalDirWorkspaceBackend::new(&root).unwrap();
        std::fs::write(backend.base_workspace_dir().join("ship.cfg"), "thruster=nominal\n").unwrap();
        std::fs::write(backend.base_memory_dir().join("episodic.json"), r#"{"step":0}"#).unwrap();

        let audit = AuditLog::open(root.join("hal-audit.jsonl")).unwrap();
        let mut mgr = WorkspaceManager::new(backend, audit);
        let p = coder_principal();

        mgr.begin_episode(&p, "ep_02", 1000).unwrap();
        mgr.snapshot_before_l1(&p, "ep_02", "step_01", "pre-edit", 1100)
            .unwrap();

        let ws_dir = mgr.backend().episode_workspace_dir("agent-coder", "ep_02").unwrap();
        let mem_dir = mgr.backend().episode_memory_dir("agent-coder", "ep_02").unwrap();

        // Simulate destructive edit + rogue file + false completion memory
        std::fs::remove_file(ws_dir.join("ship.cfg")).unwrap();
        std::fs::write(ws_dir.join("rogue.sh"), "#!/bin/sh\nrm -rf /\n").unwrap();
        std::fs::write(mem_dir.join("episodic.json"), r#"{"step":99,"done":true}"#).unwrap();

        let diff = mgr.backend().diff_against_base("agent-coder", "ep_02").unwrap();
        assert_eq!(diff.deleted, vec!["ship.cfg"]);
        assert_eq!(diff.added, vec!["rogue.sh"]);

        // Atomic dual-rollback reverts BOTH disk and memory synchronously
        mgr.rollback_dual_snapshot(&p, "ep_02", "step_01", 1200).unwrap();
        assert_eq!(
            std::fs::read_to_string(ws_dir.join("ship.cfg")).unwrap(),
            "thruster=nominal\n"
        );
        assert!(!ws_dir.join("rogue.sh").exists());
        assert_eq!(
            std::fs::read_to_string(mem_dir.join("episodic.json")).unwrap(),
            r#"{"step":0}"#
        );

        // L2 approval required before merging
        assert!(matches!(
            mgr.commit_episode(&p, "ep_02", None, 1300),
            Err(WorkspaceError::ApprovalRequired(_))
        ));
        assert!(mgr.commit_episode(&p, "ep_02", Some("appr_42"), 1400).is_ok());

        let _ = std::fs::remove_dir_all(root);
    }
}
