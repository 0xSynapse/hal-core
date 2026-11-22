use crate::spec::{is_valid_sandbox_id, SandboxSpec};
use hal_audit::{AuditInput, AuditLog};
use hal_os_hal::SandboxBackend;
use hal_proto::{verify_attenuation, verify_token_signature, AgentPrincipal, CapabilityToken};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::Path;

/// Tracked jail/sandbox instance managed by `hal-sandbox`.
#[derive(Debug, Clone)]
pub struct SandboxRecord {
    pub spec: SandboxSpec,
    pub parent_sandbox_id: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxError {
    pub code: &'static str,
    pub reason: String,
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for SandboxError {}

/// FreeBSD Jail + RCTL + nullfs-UDS lifecycle orchestrator with monotonic child narrowing.
pub struct SandboxOrchestrator<S: SandboxBackend> {
    backend: S,
    token_secret: Vec<u8>,
    sandboxes: HashMap<String, SandboxRecord>,
    audit: AuditLog,
}

impl<S: SandboxBackend> SandboxOrchestrator<S> {
    #[must_use]
    pub fn new(backend: S, token_secret: Vec<u8>, audit: AuditLog) -> Self {
        Self {
            backend,
            token_secret,
            sandboxes: HashMap::new(),
            audit,
        }
    }

    #[must_use]
    pub fn backend(&self) -> &S {
        &self.backend
    }

    #[must_use]
    pub fn get(&self, sandbox_id: &str) -> Option<&SandboxRecord> {
        self.sandboxes.get(sandbox_id)
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sandboxes.values().filter(|r| r.active).count()
    }

    fn log_event(
        &mut self,
        now_ms: u64,
        principal: &AgentPrincipal,
        sandbox_id: &str,
        action: &str,
        summary: String,
    ) {
        let _ = self.audit.append(AuditInput {
            ts_ms: now_ms,
            principal: principal.clone(),
            episode_id: "sandbox".to_string(),
            target_path: format!("/sys/jails/{sandbox_id}"),
            action: action.to_string(),
            trigger_event_ids: Vec::new(),
            proposal_id: None,
            decision_summary: summary,
            workspace_snapshot_id: None,
        });
    }

    fn validate_new_spec(&self, spec: &SandboxSpec, now_ms: u64) -> Result<(), SandboxError> {
        if !is_valid_sandbox_id(&spec.sandbox_id) || spec.agent_id.is_empty() {
            return Err(SandboxError {
                code: "INVALID_SANDBOX_SPEC",
                reason: format!("invalid sandbox_id '{}' or empty agent_id", spec.sandbox_id),
            });
        }
        if self.sandboxes.contains_key(&spec.sandbox_id) {
            return Err(SandboxError {
                code: "DUPLICATE_SANDBOX_ID",
                reason: format!("sandbox '{}' already exists", spec.sandbox_id),
            });
        }
        if spec.rctl_limits.memoryuse_mb == 0
            || spec.rctl_limits.maxproc == 0
            || spec.rctl_limits.pcpu_pct == 0
        {
            return Err(SandboxError {
                code: "INVALID_RCTL_LIMITS",
                reason: "memoryuse_mb, maxproc, and pcpu_pct must all be > 0".to_string(),
            });
        }
        if spec.uds_host_dir.as_os_str().is_empty() {
            return Err(SandboxError {
                code: "INVALID_UDS_PATH",
                reason: "uds_host_dir cannot be empty".to_string(),
            });
        }
        for rec in self.sandboxes.values().filter(|r| r.active) {
            if paths_overlap(&rec.spec.uds_host_dir, &spec.uds_host_dir) {
                return Err(SandboxError {
                    code: "UDS_PATH_COLLISION",
                    reason: format!(
                        "uds_host_dir '{}' overlaps active sandbox '{}'",
                        spec.uds_host_dir.display(),
                        rec.spec.sandbox_id
                    ),
                });
            }
        }
        if !verify_token_signature(&spec.cap_token, &self.token_secret) {
            return Err(SandboxError {
                code: "INVALID_CAP_TOKEN",
                reason: "sandbox capability token HMAC verification failed".to_string(),
            });
        }
        if spec.cap_token.expires_at_ms <= now_ms {
            return Err(SandboxError {
                code: "TOKEN_EXPIRED",
                reason: "sandbox capability token is expired".to_string(),
            });
        }
        if spec.cap_token.subject_agent_id != spec.agent_id {
            return Err(SandboxError {
                code: "TOKEN_SUBJECT_MISMATCH",
                reason: format!(
                    "token subject '{}' does not match agent_id '{}'",
                    spec.cap_token.subject_agent_id, spec.agent_id
                ),
            });
        }
        Ok(())
    }

    /// Starts a resident agent Jail with RCTL hard limits and an exclusive UDS mount directory.
    pub fn spawn_resident(
        &mut self,
        caller: &AgentPrincipal,
        spec: SandboxSpec,
        now_ms: u64,
    ) -> Result<SandboxRecord, SandboxError> {
        if let Err(err) = self.validate_new_spec(&spec, now_ms) {
            self.log_event(
                now_ms,
                caller,
                &spec.sandbox_id,
                "spawn_resident",
                format!("Deny({}: {})", err.code, err.reason),
            );
            return Err(err);
        }

        self.start_backend(&spec)?;
        let record = SandboxRecord {
            spec: spec.clone(),
            parent_sandbox_id: None,
            active: true,
        };
        self.sandboxes.insert(spec.sandbox_id.clone(), record.clone());
        self.log_event(
            now_ms,
            caller,
            &spec.sandbox_id,
            "spawn_resident",
            format!(
                "Started(agent={}, mem={}M, proc={}, pcpu={}%)",
                spec.agent_id,
                spec.rctl_limits.memoryuse_mb,
                spec.rctl_limits.maxproc,
                spec.rctl_limits.pcpu_pct
            ),
        );
        Ok(record)
    }

    /// Starts an ephemeral child worker Jail enforcing BOTH token attenuation and RCTL narrowing.
    pub fn spawn_ephemeral_worker(
        &mut self,
        caller: &AgentPrincipal,
        parent_sandbox_id: &str,
        parent_token: &CapabilityToken,
        child_spec: SandboxSpec,
        now_ms: u64,
    ) -> Result<SandboxRecord, SandboxError> {
        let Some(parent) = self.sandboxes.get(parent_sandbox_id).cloned() else {
            return Err(SandboxError {
                code: "PARENT_SANDBOX_INACTIVE",
                reason: format!("parent sandbox '{parent_sandbox_id}' does not exist"),
            });
        };
        if !parent.active {
            return Err(SandboxError {
                code: "PARENT_SANDBOX_INACTIVE",
                reason: format!("parent sandbox '{parent_sandbox_id}' is not active"),
            });
        }
        if parent_token.subject_agent_id != parent.spec.agent_id {
            return Err(SandboxError {
                code: "ATTENUATION_DENIED",
                reason: "parent_token does not belong to parent sandbox agent".to_string(),
            });
        }
        if child_spec.parent_agent_id.as_deref() != Some(parent.spec.agent_id.as_str()) {
            return Err(SandboxError {
                code: "ATTENUATION_DENIED",
                reason: format!(
                    "child_spec.parent_agent_id must be '{}'",
                    parent.spec.agent_id
                ),
            });
        }

        if let Err(err) =
            verify_attenuation(parent_token, &child_spec.cap_token, &self.token_secret, now_ms)
        {
            let serr = SandboxError {
                code: "ATTENUATION_DENIED",
                reason: err.to_string(),
            };
            self.log_event(
                now_ms,
                caller,
                &child_spec.sandbox_id,
                "spawn_ephemeral_worker",
                format!("Deny({}: {})", serr.code, serr.reason),
            );
            return Err(serr);
        }

        if child_spec.rctl_limits.memoryuse_mb > parent.spec.rctl_limits.memoryuse_mb
            || child_spec.rctl_limits.maxproc > parent.spec.rctl_limits.maxproc
            || child_spec.rctl_limits.pcpu_pct > parent.spec.rctl_limits.pcpu_pct
        {
            let serr = SandboxError {
                code: "RCTL_ESCALATION_DENIED",
                reason: format!(
                    "child RCTL {:?} exceeds parent {:?}",
                    child_spec.rctl_limits, parent.spec.rctl_limits
                ),
            };
            self.log_event(
                now_ms,
                caller,
                &child_spec.sandbox_id,
                "spawn_ephemeral_worker",
                format!("Deny({}: {})", serr.code, serr.reason),
            );
            return Err(serr);
        }

        if let Err(err) = self.validate_new_spec(&child_spec, now_ms) {
            self.log_event(
                now_ms,
                caller,
                &child_spec.sandbox_id,
                "spawn_ephemeral_worker",
                format!("Deny({}: {})", err.code, err.reason),
            );
            return Err(err);
        }

        self.start_backend(&child_spec)?;
        let record = SandboxRecord {
            spec: child_spec.clone(),
            parent_sandbox_id: Some(parent_sandbox_id.to_string()),
            active: true,
        };
        self.sandboxes
            .insert(child_spec.sandbox_id.clone(), record.clone());
        self.log_event(
            now_ms,
            caller,
            &child_spec.sandbox_id,
            "spawn_ephemeral_worker",
            format!(
                "Started(parent={parent_sandbox_id}, agent={}, mem={}M)",
                child_spec.agent_id, child_spec.rctl_limits.memoryuse_mb
            ),
        );
        Ok(record)
    }

    /// Surgically stops all sandboxes belonging to `target_agent_id` (plus its spawned workers),
    /// leaving all other healthy agents running uninterrupted.
    pub fn freeze_agent_sandboxes(
        &mut self,
        caller: &AgentPrincipal,
        target_agent_id: &str,
        caller_is_oob: bool,
        caller_is_watchdog: bool,
        now_ms: u64,
    ) -> Result<Vec<String>, SandboxError> {
        if !caller_is_oob && !caller_is_watchdog {
            return Err(SandboxError {
                code: "UNAUTHORIZED",
                reason: "only hal-oob or hal-watchdog may freeze sandboxes".to_string(),
            });
        }

        let mut victim_ids: BTreeSet<String> = self
            .sandboxes
            .values()
            .filter(|r| {
                r.active
                    && (r.spec.agent_id == target_agent_id
                        || r.spec.parent_agent_id.as_deref() == Some(target_agent_id))
            })
            .map(|r| r.spec.sandbox_id.clone())
            .collect();

        // Include nested descendant sandboxes whose parent_sandbox_id was marked for stop
        loop {
            let mut added = false;
            for rec in self.sandboxes.values().filter(|r| r.active) {
                if rec
                    .parent_sandbox_id
                    .as_ref()
                    .is_some_and(|pid| victim_ids.contains(pid))
                    && victim_ids.insert(rec.spec.sandbox_id.clone())
                {
                    added = true;
                }
            }
            if !added {
                break;
            }
        }

        let mut stopped = Vec::new();
        for sid in victim_ids {
            self.backend.stop_jail(&sid).map_err(|e| SandboxError {
                code: "SANDBOX_BACKEND_ERROR",
                reason: e.to_string(),
            })?;
            if let Some(rec) = self.sandboxes.get_mut(&sid) {
                rec.active = false;
            }
            stopped.push(sid);
        }

        self.log_event(
            now_ms,
            caller,
            target_agent_id,
            "freeze_agent_sandboxes",
            format!("SurgicalFreeze(stopped={stopped:?})"),
        );
        Ok(stopped)
    }

    /// Global `FROZEN` emergency breaker stopping all active cognitive sandboxes (`jail -r`).
    pub fn terminate_all_cognitive_sandboxes(
        &mut self,
        caller: &AgentPrincipal,
        caller_is_oob: bool,
        caller_is_watchdog: bool,
        now_ms: u64,
    ) -> Result<Vec<String>, SandboxError> {
        if !caller_is_oob && !caller_is_watchdog {
            return Err(SandboxError {
                code: "UNAUTHORIZED",
                reason: "only hal-oob or hal-watchdog may terminate all cognitive sandboxes"
                    .to_string(),
            });
        }

        let ids: Vec<String> = self
            .sandboxes
            .values()
            .filter(|r| r.active)
            .map(|r| r.spec.sandbox_id.clone())
            .collect();
        for sid in &ids {
            self.backend.stop_jail(sid).map_err(|e| SandboxError {
                code: "SANDBOX_BACKEND_ERROR",
                reason: e.to_string(),
            })?;
            if let Some(rec) = self.sandboxes.get_mut(sid) {
                rec.active = false;
            }
        }
        self.log_event(
            now_ms,
            caller,
            "all",
            "terminate_all_cognitive_sandboxes",
            format!("GlobalFrozen(stopped={ids:?})"),
        );
        Ok(ids)
    }

    fn start_backend(&self, spec: &SandboxSpec) -> Result<(), SandboxError> {
        self.backend
            .apply_rctl_limits(&spec.sandbox_id, &spec.rctl_limits)
            .map_err(|e| SandboxError {
                code: "RCTL_APPLY_FAILED",
                reason: e.to_string(),
            })?;
        self.backend
            .start_jail(&spec.sandbox_id)
            .map_err(|e| SandboxError {
                code: "JAIL_START_FAILED",
                reason: e.to_string(),
            })?;
        Ok(())
    }
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}
