use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// Single cognitive episodic memory record stored inside `halpool/memory/active/<agent>/<ep>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub seq: u64,
    pub ts_ms: u64,
    pub kind: String,
    pub summary: String,
    pub trigger_event_ids: Vec<String>,
}

/// Disk-backed episodic memory store synchronized with `hal-workspace` atomic dual snapshots.
#[derive(Debug, Clone)]
pub struct EpisodicMemoryStore {
    dir: PathBuf,
    file_path: PathBuf,
    entries: Vec<MemoryEntry>,
}

impl EpisodicMemoryStore {
    pub fn load_or_init(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let file_path = dir.join("episodic.json");
        let mut store = Self {
            dir,
            file_path,
            entries: Vec::new(),
        };
        if store.file_path.exists() {
            store.reload()?;
        } else {
            store.persist()?;
        }
        Ok(store)
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[must_use]
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    #[must_use]
    pub fn entries(&self) -> &[MemoryEntry] {
        &self.entries
    }

    #[must_use]
    pub fn contains_summary(&self, needle: &str) -> bool {
        self.entries.iter().any(|e| e.summary.contains(needle))
    }

    /// Reloads memory entries directly from disk (must be called after a dual-snapshot rollback).
    pub fn reload(&mut self) -> io::Result<()> {
        if !self.file_path.exists() {
            self.entries.clear();
            return Ok(());
        }
        let raw = std::fs::read_to_string(&self.file_path)?;
        if raw.trim().is_empty() {
            self.entries.clear();
            return Ok(());
        }
        self.entries = serde_json::from_str(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.entries)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        std::fs::write(&self.file_path, bytes)
    }

    pub fn record(
        &mut self,
        ts_ms: u64,
        kind: &str,
        summary: &str,
        trigger_event_ids: Vec<String>,
    ) -> io::Result<MemoryEntry> {
        let seq = self.entries.last().map_or(1, |e| e.seq + 1);
        let entry = MemoryEntry {
            seq,
            ts_ms,
            kind: kind.to_string(),
            summary: summary.to_string(),
            trigger_event_ids,
        };
        self.entries.push(entry.clone());
        self.persist()?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn memory_roundtrip_and_external_snapshot_restore() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "hal_brain_mem_{}_{}",
            std::process::id(),
            nanos % 1_000_000_000
        ));
        let mut store = EpisodicMemoryStore::load_or_init(&dir).unwrap();
        store
            .record(1000, "observation", "initial baseline clean", vec![])
            .unwrap();
        let snapshot_bytes = std::fs::read(store.file_path()).unwrap();

        store
            .record(1100, "claim", "Configuration updated safely", vec![])
            .unwrap();
        assert!(store.contains_summary("Configuration updated safely"));

        std::fs::write(store.file_path(), snapshot_bytes).unwrap();
        store.reload().unwrap();
        assert!(!store.contains_summary("Configuration updated safely"));
        assert_eq!(store.entries().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
