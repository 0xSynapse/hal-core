use hal_os_hal::{DualSnapshotRequest, HalOsError, WorkspaceBackend};
use hal_proto::DualSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Structured file changes between an agent episode workspace and the clean base workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceDiff {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
}

impl WorkspaceDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }
}

fn validate_leaf(val: &str, label: &str) -> Result<(), HalOsError> {
    if val.is_empty()
        || !val
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        || val.contains("..")
    {
        return Err(HalOsError::InvalidArgument(format!(
            "invalid {label} '{val}'"
        )));
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), HalOsError> {
    if !src.exists() {
        fs::create_dir_all(dst)?;
        return Ok(());
    }
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn clear_and_restore_dir(snapshot_dir: &Path, live_dir: &Path) -> Result<(), HalOsError> {
    if live_dir.exists() {
        fs::remove_dir_all(live_dir)?;
    }
    copy_dir_recursive(snapshot_dir, live_dir)
}

fn collect_files(base: &Path, cur: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), HalOsError> {
    if !cur.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(cur)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_files(base, &path, out)?;
        } else if entry.file_type()?.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| HalOsError::InvalidArgument(e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, fs::read(&path)?);
        }
    }
    Ok(())
}

/// Real filesystem-backed Copy-on-Write & dual-snapshot backend for Linux CI and dev testbeds.
#[derive(Debug, Clone)]
pub struct LocalDirWorkspaceBackend {
    root: PathBuf,
}

impl LocalDirWorkspaceBackend {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, HalOsError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("halpool/workspaces/base"))?;
        fs::create_dir_all(root.join("halpool/workspaces/active"))?;
        fs::create_dir_all(root.join("halpool/memory/base"))?;
        fs::create_dir_all(root.join("halpool/memory/active"))?;
        fs::create_dir_all(root.join("snapshots"))?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn base_workspace_dir(&self) -> PathBuf {
        self.root.join("halpool/workspaces/base")
    }

    #[must_use]
    pub fn base_memory_dir(&self) -> PathBuf {
        self.root.join("halpool/memory/base")
    }

    pub fn episode_workspace_dir(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<PathBuf, HalOsError> {
        validate_leaf(agent_id, "agent_id")?;
        validate_leaf(episode_id, "episode_id")?;
        Ok(self
            .root
            .join(format!("halpool/workspaces/active/{agent_id}/{episode_id}")))
    }

    pub fn episode_memory_dir(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<PathBuf, HalOsError> {
        validate_leaf(agent_id, "agent_id")?;
        validate_leaf(episode_id, "episode_id")?;
        Ok(self
            .root
            .join(format!("halpool/memory/active/{agent_id}/{episode_id}")))
    }

    fn resolve_dataset_dir(&self, ds: &str) -> Result<PathBuf, HalOsError> {
        if !(ds.starts_with("halpool/workspaces/active/") || ds.starts_with("halpool/memory/active/"))
            || ds.contains("..")
            || ds.contains('\0')
        {
            return Err(HalOsError::InvalidArgument(format!(
                "dataset '{ds}' outside active halpool roots"
            )));
        }
        Ok(self.root.join(ds))
    }

    fn snapshot_pair_dir(
        &self,
        ws_ds: &str,
        mem_ds: &str,
        tag: &str,
    ) -> Result<(PathBuf, PathBuf), HalOsError> {
        validate_leaf(tag, "snapshot_tag")?;
        let key = format!("{}___{}__{tag}", ws_ds.replace('/', "_"), mem_ds.replace('/', "_"));
        let base = self.root.join("snapshots").join(key);
        Ok((base.join("ws"), base.join("mem")))
    }

    /// Computes exact diff between an episode's CoW workspace and the clean base workspace.
    pub fn diff_against_base(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<WorkspaceDiff, HalOsError> {
        let base_dir = self.base_workspace_dir();
        let ep_dir = self.episode_workspace_dir(agent_id, episode_id)?;
        let mut base_files = BTreeMap::new();
        let mut ep_files = BTreeMap::new();
        collect_files(&base_dir, &base_dir, &mut base_files)?;
        collect_files(&ep_dir, &ep_dir, &mut ep_files)?;

        let all_keys: BTreeSet<String> = base_files
            .keys()
            .chain(ep_files.keys())
            .cloned()
            .collect();
        let mut diff = WorkspaceDiff::default();
        for key in all_keys {
            match (base_files.get(&key), ep_files.get(&key)) {
                (None, Some(_)) => diff.added.push(key),
                (Some(_), None) => diff.deleted.push(key),
                (Some(a), Some(b)) if a != b => diff.modified.push(key),
                _ => {}
            }
        }
        Ok(diff)
    }

    /// Promotes an approved episode's CoW changes back into the clean base workspace.
    pub fn merge_to_base(&self, agent_id: &str, episode_id: &str) -> Result<(), HalOsError> {
        let ep_dir = self.episode_workspace_dir(agent_id, episode_id)?;
        if !ep_dir.exists() {
            return Err(HalOsError::NotFound(ep_dir.display().to_string()));
        }
        clear_and_restore_dir(&ep_dir, &self.base_workspace_dir())
    }
}

impl WorkspaceBackend for LocalDirWorkspaceBackend {
    fn clone_episode_datasets(
        &self,
        agent_id: &str,
        episode_id: &str,
    ) -> Result<(String, String), HalOsError> {
        validate_leaf(agent_id, "agent_id")?;
        validate_leaf(episode_id, "episode_id")?;
        let ws_ds = format!("halpool/workspaces/active/{agent_id}/{episode_id}");
        let mem_ds = format!("halpool/memory/active/{agent_id}/{episode_id}");
        let ws_dir = self.resolve_dataset_dir(&ws_ds)?;
        let mem_dir = self.resolve_dataset_dir(&mem_ds)?;
        copy_dir_recursive(&self.base_workspace_dir(), &ws_dir)?;
        copy_dir_recursive(&self.base_memory_dir(), &mem_dir)?;
        Ok((ws_ds, mem_ds))
    }

    fn destroy_episode_datasets(
        &self,
        workspace_dataset: &str,
        memory_dataset: &str,
    ) -> Result<(), HalOsError> {
        let ws_dir = self.resolve_dataset_dir(workspace_dataset)?;
        let mem_dir = self.resolve_dataset_dir(memory_dataset)?;
        if ws_dir.exists() {
            fs::remove_dir_all(ws_dir)?;
        }
        if mem_dir.exists() {
            fs::remove_dir_all(mem_dir)?;
        }
        Ok(())
    }

    fn create_dual_snapshot(
        &self,
        req: &DualSnapshotRequest<'_>,
    ) -> Result<DualSnapshot, HalOsError> {
        let ws_dir = self.resolve_dataset_dir(req.workspace_dataset)?;
        let mem_dir = self.resolve_dataset_dir(req.memory_dataset)?;
        let (ws_snap, mem_snap) =
            self.snapshot_pair_dir(req.workspace_dataset, req.memory_dataset, req.snapshot_tag)?;
        clear_and_restore_dir(&ws_dir, &ws_snap)?;
        clear_and_restore_dir(&mem_dir, &mem_snap)?;
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
        let ws_dir = self.resolve_dataset_dir(workspace_dataset)?;
        let mem_dir = self.resolve_dataset_dir(memory_dataset)?;
        let (ws_snap, mem_snap) =
            self.snapshot_pair_dir(workspace_dataset, memory_dataset, snapshot_tag)?;
        if !ws_snap.exists() || !mem_snap.exists() {
            return Err(HalOsError::NotFound(format!(
                "dual snapshot '{snapshot_tag}' not found"
            )));
        }
        clear_and_restore_dir(&ws_snap, &ws_dir)?;
        clear_and_restore_dir(&mem_snap, &mem_dir)?;
        Ok(())
    }
}
