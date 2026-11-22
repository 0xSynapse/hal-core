//! Ephemeral FreeBSD No-IP / VNET Jail + RCTL sandbox orchestrator (`hal-sandbox`).

pub mod orchestrator;
pub mod spec;

pub use orchestrator::{SandboxError, SandboxOrchestrator, SandboxRecord};
pub use spec::{render_jail_conf, render_rctl_rules, NetworkMode, SandboxSpec};
