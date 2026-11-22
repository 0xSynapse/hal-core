use hal_os_hal::RctlLimits;
use hal_proto::CapabilityToken;
use std::path::PathBuf;

/// Network isolation topology assigned to an agent or worker Jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    NoIp,
    BrokeredVnet { vnet_if: String },
}

/// Complete specification for launching a resident agent or ephemeral child worker sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    pub sandbox_id: String,
    pub agent_id: String,
    pub parent_agent_id: Option<String>,
    pub network_mode: NetworkMode,
    pub rctl_limits: RctlLimits,
    pub uds_host_dir: PathBuf,
    pub workspace_mount: Option<PathBuf>,
    pub cap_token: CapabilityToken,
}

/// Validates a FreeBSD Jail / RCTL identifier contains no traversal or shell metacharacters.
#[must_use]
pub fn is_valid_sandbox_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Renders a FreeBSD `/etc/jail.conf.d/<sandbox_id>.conf` stanza matching Phase 0 hardening.
#[must_use]
pub fn render_jail_conf(spec: &SandboxSpec) -> String {
    let uds = spec.uds_host_dir.display();
    match &spec.network_mode {
        NetworkMode::NoIp => format!(
            "{id} {{\n  host.hostname = \"{id}.hal.local\";\n  ip4 = disable;\n  ip6 = disable;\n  allow.raw_sockets = 0;\n  allow.mount = 0;\n  exec.prepare = \"mkdir -p {uds}\";\n  persist;\n}}\n",
            id = spec.sandbox_id,
        ),
        NetworkMode::BrokeredVnet { vnet_if } => format!(
            "{id} {{\n  host.hostname = \"{id}.hal.local\";\n  vnet;\n  vnet.interface = \"{vnet_if}\";\n  allow.raw_sockets = 0;\n  allow.mount = 0;\n  exec.prepare = \"mkdir -p {uds}\";\n  persist;\n}}\n",
            id = spec.sandbox_id,
        ),
    }
}

/// Renders deterministic FreeBSD `rctl.conf` rules bound to `jail:<sandbox_id>`.
#[must_use]
pub fn render_rctl_rules(spec: &SandboxSpec) -> Vec<String> {
    vec![
        format!(
            "jail:{}:memoryuse:deny={}M",
            spec.sandbox_id, spec.rctl_limits.memoryuse_mb
        ),
        format!(
            "jail:{}:maxproc:deny={}",
            spec.sandbox_id, spec.rctl_limits.maxproc
        ),
        format!(
            "jail:{}:pcpu:deny={}",
            spec.sandbox_id, spec.rctl_limits.pcpu_pct
        ),
    ]
}
