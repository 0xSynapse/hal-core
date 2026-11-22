//! Deterministic HAL-OS policy engine, IPC matrix, hard invariants,
//! and transitive taint state machine.

pub mod engine;
pub mod invariants;
pub mod ipc_matrix;
pub mod taint;

pub use engine::{PolicyConfig, PolicyEngine, PolicyError};
pub use invariants::check_hard_invariants;
pub use ipc_matrix::{DenyAssertRule, IpcAllowRule, IpcDenyReason, IpcMatrix, IpcMatrixError};
pub use taint::TaintTracker;
