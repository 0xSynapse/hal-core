//! OS abstraction traits and FreeBSD 14 / Linux dev implementations for HAL-OS.

pub mod append_only;
pub mod backends;
pub mod capsicum;
pub mod peercred;

pub use append_only::{AppendOnlyGuard, MockAppendOnlyGuard, OsAppendOnlyGuard};
pub use backends::{
    DualSnapshotRequest, FirewallBackend, FreeBsdJailBackend, FreeBsdPfBackend,
    FreeBsdZfsWorkspaceBackend, HalOsError, MockFirewallBackend, MockSandboxBackend,
    MockWorkspaceBackend, SandboxBackend, WorkspaceBackend,
};
pub use capsicum::{CapsicumGuard, OsCapsicumGuard};
pub use peercred::{MockPeerCredProvider, OsPeerCredProvider, PeerCred, PeerCredProvider};
