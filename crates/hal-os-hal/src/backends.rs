use hal_proto::DualSnapshot;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::process::Command;
use std::sync::Mutex;

/// Errors returned by OS backend adapters (`hal-os-hal`).
#[derive(Debug)]
pub enum HalOsError {
    Io(io::Error),
    CommandFailed { cmd: String, stderr: String },
    InvalidArgument(String),
    NotFound(String),
}

impl fmt::Display for HalOsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::CommandFailed { cmd, stderr } => {
                write!(f, "OS command '{cmd}' failed: {stderr}")
            }
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
        }
    }
}

impl std::error::Error for HalOsError {}

impl From<io::Error> for HalOsError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Parameters required to create an atomic workspace + AI memory dual snapshot.
#[derive(Debug, Clone, Copy)]
pub struct DualSnapshotRequest<'a> {
    pub workspace_dataset: &'a str,
    pub memory_dataset: &'a str,
    pub snapshot_tag: &'a str,
    pub reason: &'a str,
    pub agent_id: &'a str,
    pub episode_id: &'a str,
    pub now_ms: u64,
}

/// Hard per-jail RCTL resource limits (`kern.racct.enable="1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RctlLimits {
    pub memoryuse_mb: u32,
    pub maxproc: u32,
    pub pcpu_pct: u32,
}

/// OS abstraction for atomic workspace + memory dual snapshots (`hal-workspace`).
pub trait WorkspaceBackend: Send + Sync {
    fn clone_episode_datasets(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<(String, String), HalOsError>;

    fn destroy_episode_datasets(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
    ) -> Result<(), HalOsError>;

    fn create_dual_snapshot(
        &self,
        req: &DualSnapshotRequest<'_>,
    ) -> Result<DualSnapshot, HalOsError>;

    fn rollback_dual_snapshot(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
        snapshot_tag: &str,
    ) -> Result<(), HalOsError>;
}

/// OS abstraction for FreeBSD Jail lifecycle control (`hal-sandbox` / `hal-watchdog`).
pub trait SandboxBackend: Send + Sync {
    fn apply_rctl_limits(&self, jail_name: &str, limits: &RctlLimits) -> Result<(), HalOsError>;
    fn start_jail(&self, jail_name: &str) -> Result<(), HalOsError>;
    fn stop_jail(&self, jail_name: &str) -> Result<(), HalOsError>;
    fn is_jail_running(&self, jail_name: &str) -> Result<bool, HalOsError>;
}

/// OS abstraction for host PF firewall health and broker enforcement (`hal-watchdog`).
pub trait FirewallBackend: Send + Sync {
    fn is_enabled(&self) -> Result<bool, HalOsError>;
    fn pf_blocked_user_egress_active(&self) -> Result<bool, HalOsError>;
}

fn validate_safe_ident(value: &str, label: &str) -> Result<(), HalOsError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'))
        || value.contains("..")
    {
        return Err(HalOsError::InvalidArgument(format!(
            "unsafe {label} '{value}'"
        )));
    }
    Ok(())
}

fn validate_leaf_ident(value: &str, label: &str) -> Result<(), HalOsError> {
    if value.contains('/') {
        return Err(HalOsError::InvalidArgument(format!(
            "unsafe {label} '{value}'"
        )));
    }
    validate_safe_ident(value, label)
}

/// FreeBSD OpenZFS CLI implementation of `WorkspaceBackend`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreeBsdZfsWorkspaceBackend;

impl WorkspaceBackend for FreeBsdZfsWorkspaceBackend {
    fn clone_episode_datasets(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<(String, String), HalOsError> {
        validate_leaf_ident(agent_id, "agent_id")?;
        validate_leaf_ident(episode_id, "episode_id")?;
        let ws_ds = format!("halpool/workspaces/active/{agent_id}/{episode_id}");
        let mem_ds = format!("halpool/memory/active/{agent_id}/{episode_id}");
        for ds in [&ws_ds, &mem_ds] {
            let out = Command::new("zfs").args(["create", "-p", ds]).output()?;
            if !out.status.success() {
                return Err(HalOsError::CommandFailed {
                    cmd: format!("zfs create -p {ds}"),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                });
            }
        }
        Ok((ws_ds, mem_ds))
    }

    fn destroy_episode_datasets(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
    ) -> Result<(), HalOsError> {
        validate_safe_ident(workspace_dataset, "workspace_dataset")?;
        validate_safe_ident(memory_dataset, "memory_dataset")?;
        if !workspace_dataset.starts_with("halpool/workspaces/active/")
            || !memory_dataset.starts_with("halpool/memory/active/")
        {
            return Err(HalOsError::InvalidArgument(
                "destroy_episode_datasets only permits active episode datasets".to_string(),
            ));
        }
        for ds in [workspace_dataset, memory_dataset] {
            let out = Command::new("zfs").args(["destroy", "-r", ds]).output()?;
            if !out.status.success() {
                return Err(HalOsError::CommandFailed {
                    cmd: format!("zfs destroy -r {ds}"),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                });
            }
        }
        Ok(())
    }

    fn create_dual_snapshot(
        &self,
        req: &DualSnapshotRequest<'_>,
    ) -> Result<DualSnapshot, HalOsError> {
        validate_safe_ident(req.workspace_dataset, "workspace_dataset")?;
        validate_safe_ident(req.memory_dataset, "memory_dataset")?;
        validate_safe_ident(req.snapshot_tag, "snapshot_tag")?;

        let ws_snap = format!("{}@{}", req.workspace_dataset, req.snapshot_tag);
        let mem_snap = format!("{}@{}", req.memory_dataset, req.snapshot_tag);
        let out = Command::new("zfs")
            .arg("snapshot")
            .arg(&ws_snap)
            .arg(&mem_snap)
            .output()?;
        if !out.status.success() {
            return Err(HalOsError::CommandFailed {
                cmd: format!("zfs snapshot {ws_snap} {mem_snap}"),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(DualSnapshot {
            snapshot_tag: req.snapshot_tag.to_string(),
            agent_id: req.agent_id.to_string(),
            episode_id: req.episode_id.to_string(),
            workspace_dataset: req.workspace_dataset.to_string(),
            memory_dataset: req.memory_dataset.to_string(),
            created_at_ms: req.now_ms,
            reason: req.reason.to_string(),
        })
    }

    fn rollback_dual_snapshot(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
        snapshot_tag: &str,
    ) -> Result<(), HalOsError> {
        validate_safe_ident(workspace_dataset, "workspace_dataset")?;
        validate_safe_ident(memory_dataset, "memory_dataset")?;
        validate_safe_ident(snapshot_tag, "snapshot_tag")?;

        for ds in [workspace_dataset, memory_dataset] {
            let snap = format!("{ds}@{snapshot_tag}");
            let out = Command::new("zfs")
                .args(["rollback", "-r", &snap])
                .output()?;
            if !out.status.success() {
                return Err(HalOsError::CommandFailed {
                    cmd: format!("zfs rollback -r {snap}"),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                });
            }
        }
        Ok(())
    }
}

/// FreeBSD `service jail` / `jls` implementation of `SandboxBackend`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreeBsdJailBackend;

impl SandboxBackend for FreeBsdJailBackend {
    fn apply_rctl_limits(&self, jail_name: &str, limits: &RctlLimits) -> Result<(), HalOsError> {
        validate_leaf_ident(jail_name, "jail_name")?;
        if limits.memoryuse_mb == 0 || limits.maxproc == 0 || limits.pcpu_pct == 0 {
            return Err(HalOsError::InvalidArgument(
                "rctl limits must all be > 0".to_string(),
            ));
        }
        let rules = [
            format!("jail:{jail_name}:memoryuse:deny={}M", limits.memoryuse_mb),
            format!("jail:{jail_name}:maxproc:deny={}", limits.maxproc),
            format!("jail:{jail_name}:pcpu:deny={}", limits.pcpu_pct),
        ];
        for rule in &rules {
            let out = Command::new("rctl").args(["-a", rule]).output()?;
            if !out.status.success() {
                return Err(HalOsError::CommandFailed {
                    cmd: format!("rctl -a {rule}"),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
                });
            }
        }
        Ok(())
    }

    fn start_jail(&self, jail_name: &str) -> Result<(), HalOsError> {
        validate_safe_ident(jail_name, "jail_name")?;
        let out = Command::new("service")
            .args(["jail", "onestart", jail_name])
            .output()?;
        if !out.status.success() {
            return Err(HalOsError::CommandFailed {
                cmd: format!("service jail onestart {jail_name}"),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }

    fn stop_jail(&self, jail_name: &str) -> Result<(), HalOsError> {
        validate_safe_ident(jail_name, "jail_name")?;
        let out = Command::new("service")
            .args(["jail", "onestop", jail_name])
            .output()?;
        if !out.status.success() {
            return Err(HalOsError::CommandFailed {
                cmd: format!("service jail onestop {jail_name}"),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }

    fn is_jail_running(&self, jail_name: &str) -> Result<bool, HalOsError> {
        validate_safe_ident(jail_name, "jail_name")?;
        let out = Command::new("jls").args(["-j", jail_name]).output()?;
        Ok(out.status.success())
    }
}

/// FreeBSD `pfctl` implementation of `FirewallBackend`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FreeBsdPfBackend;

impl FirewallBackend for FreeBsdPfBackend {
    fn is_enabled(&self) -> Result<bool, HalOsError> {
        let out = Command::new("pfctl").args(["-s", "info"]).output()?;
        if !out.status.success() {
            return Ok(false);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout.contains("Status: Enabled"))
    }

    fn pf_blocked_user_egress_active(&self) -> Result<bool, HalOsError> {
        let out = Command::new("pfctl").args(["-sr"]).output()?;
        if !out.status.success() {
            return Ok(false);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout.contains("on wan0 all") && stdout.contains("_hal_broker"))
    }
}

/// Thread-safe in-memory mock workspace backend for fast tests.
#[derive(Debug, Default)]
pub struct MockWorkspaceBackend {
    datasets: Mutex<BTreeSet<String>>,
    snapshots: Mutex<BTreeMap<String, DualSnapshot>>,
}

impl WorkspaceBackend for MockWorkspaceBackend {
    fn clone_episode_datasets(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<(String, String), HalOsError> {
        validate_leaf_ident(agent_id, "agent_id")?;
        validate_leaf_ident(episode_id, "episode_id")?;
        let ws_ds = format!("halpool/workspaces/active/{agent_id}/{episode_id}");
        let mem_ds = format!("halpool/memory/active/{agent_id}/{episode_id}");
        let mut guard = self
            .datasets
            .lock()
            .expect("MockWorkspaceBackend datasets mutex poisoned");
        guard.insert(ws_ds.clone());
        guard.insert(mem_ds.clone());
        Ok((ws_ds, mem_ds))
    }

    fn destroy_episode_datasets(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
    ) -> Result<(), HalOsError> {
        let mut guard = self
            .datasets
            .lock()
            .expect("MockWorkspaceBackend datasets mutex poisoned");
        guard.remove(workspace_dataset);
        guard.remove(memory_dataset);
        Ok(())
    }

    fn create_dual_snapshot(
        &self,
        req: &DualSnapshotRequest<'_>,
    ) -> Result<DualSnapshot, HalOsError> {
        validate_safe_ident(req.workspace_dataset, "workspace_dataset")?;
        validate_safe_ident(req.memory_dataset, "memory_dataset")?;
        validate_safe_ident(req.snapshot_tag, "snapshot_tag")?;
        let snap = DualSnapshot {
            snapshot_tag: req.snapshot_tag.to_string(),
            agent_id: req.agent_id.to_string(),
            episode_id: req.episode_id.to_string(),
            workspace_dataset: req.workspace_dataset.to_string(),
            memory_dataset: req.memory_dataset.to_string(),
            created_at_ms: req.now_ms,
            reason: req.reason.to_string(),
        };
        let key = format!(
            "{}|{}@{}",
            req.workspace_dataset, req.memory_dataset, req.snapshot_tag
        );
        self.snapshots
            .lock()
            .expect("MockWorkspaceBackend mutex poisoned")
            .insert(key, snap.clone());
        Ok(snap)
    }

    fn rollback_dual_snapshot(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
        snapshot_tag: &str,
    ) -> Result<(), HalOsError> {
        let key = format!("{workspace_dataset}|{memory_dataset}@{snapshot_tag}");
        let guard = self
            .snapshots
            .lock()
            .expect("MockWorkspaceBackend mutex poisoned");
        if guard.contains_key(&key) {
            Ok(())
        } else {
            Err(HalOsError::NotFound(key))
        }
    }
}

/// Thread-safe in-memory mock sandbox backend for fast tests.
#[derive(Debug, Default)]
pub struct MockSandboxBackend {
    running: Mutex<BTreeSet<String>>,
    limits: Mutex<BTreeMap<String, RctlLimits>>,
}

impl MockSandboxBackend {
    #[must_use]
    pub fn applied_limits(&self, jail_name: &str) -> Option<RctlLimits> {
        self.limits
            .lock()
            .expect("MockSandboxBackend limits mutex poisoned")
            .get(jail_name)
            .copied()
    }
}

impl SandboxBackend for MockSandboxBackend {
    fn apply_rctl_limits(&self, jail_name: &str, limits: &RctlLimits) -> Result<(), HalOsError> {
        validate_leaf_ident(jail_name, "jail_name")?;
        if limits.memoryuse_mb == 0 || limits.maxproc == 0 || limits.pcpu_pct == 0 {
            return Err(HalOsError::InvalidArgument(
                "rctl limits must all be > 0".to_string(),
            ));
        }
        self.limits
            .lock()
            .expect("MockSandboxBackend limits mutex poisoned")
            .insert(jail_name.to_string(), *limits);
        Ok(())
    }

    fn start_jail(&self, jail_name: &str) -> Result<(), HalOsError> {
        validate_safe_ident(jail_name, "jail_name")?;
        self.running
            .lock()
            .expect("MockSandboxBackend mutex poisoned")
            .insert(jail_name.to_string());
        Ok(())
    }

    fn stop_jail(&self, jail_name: &str) -> Result<(), HalOsError> {
        validate_safe_ident(jail_name, "jail_name")?;
        self.running
            .lock()
            .expect("MockSandboxBackend mutex poisoned")
            .remove(jail_name);
        Ok(())
    }

    fn is_jail_running(&self, jail_name: &str) -> Result<bool, HalOsError> {
        Ok(self
            .running
            .lock()
            .expect("MockSandboxBackend mutex poisoned")
            .contains(jail_name))
    }
}

/// Thread-safe mock firewall backend for fast tests.
#[derive(Debug, Clone)]
pub struct MockFirewallBackend {
    pub enabled: bool,
    pub default_deny_active: bool,
}

impl Default for MockFirewallBackend {
    fn default() -> Self {
        Self {
            enabled: true,
            default_deny_active: true,
        }
    }
}

impl FirewallBackend for MockFirewallBackend {
    fn is_enabled(&self) -> Result<bool, HalOsError> {
        Ok(self.enabled)
    }

    fn pf_blocked_user_egress_active(&self) -> Result<bool, HalOsError> {
        Ok(self.default_deny_active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_backends_roundtrip_and_reject_unsafe_identifiers() {
        let ws = MockWorkspaceBackend::default();
        let snap = ws
            .create_dual_snapshot(&DualSnapshotRequest {
                workspace_dataset: "halpool/workspaces/active/coder/ep1",
                memory_dataset: "halpool/memory/active/coder/ep1",
                snapshot_tag: "step1",
                reason: "L1 write",
                agent_id: "agent-coder",
                episode_id: "ep1",
                now_ms: 100,
            })
            .unwrap();
        assert_eq!(snap.snapshot_tag, "step1");
        assert!(ws
            .rollback_dual_snapshot(
                "halpool/workspaces/active/coder/ep1",
                "halpool/memory/active/coder/ep1",
                "step1"
            )
            .is_ok());

        let err = ws
            .create_dual_snapshot(&DualSnapshotRequest {
                workspace_dataset: "../evil",
                memory_dataset: "mem",
                snapshot_tag: "tag",
                reason: "x",
                agent_id: "a",
                episode_id: "e",
                now_ms: 1,
            })
            .unwrap_err();
        assert!(matches!(err, HalOsError::InvalidArgument(_)));

        let sb = MockSandboxBackend::default();
        sb.start_jail("agent_research").unwrap();
        assert!(sb.is_jail_running("agent_research").unwrap());
        sb.stop_jail("agent_research").unwrap();
        assert!(!sb.is_jail_running("agent_research").unwrap());
    }
}
