//! Per-agent Copy-on-Write workspace & atomic disk+memory dual-snapshot manager (`hal-workspace`).

pub mod local_cow;
pub mod manager;

pub use local_cow::{LocalDirWorkspaceBackend, WorkspaceDiff};
pub use manager::{EpisodeWorkspace, WorkspaceError, WorkspaceManager};
